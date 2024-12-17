use crate::{anydns::{CustomHandlerError, DnsSocket, DnsSocketError, RateLimiter, RateLimiterBuilder}, pubkey_parser::parse_pkarr_uri, query_matcher::create_domain_not_found_reply};
use std::{
    collections::HashMap, net::{IpAddr, SocketAddr}, num::NonZeroU32, sync::Arc
};
use tokio::sync::Mutex;

use crate::{
    bootstrap_nodes::MainlineBootstrapResolver,
    query_matcher::resolve_query,
    pkarr_cache::{CacheItem, PkarrPacketLruCache},
};
use pkarr::{dns::Packet, mainline::dht::DhtSettings, Error as PkarrError, PkarrClient, PkarrClientAsync, PublicKey};

#[derive(Clone, Debug)]
pub struct ResolverSettings {
    /// Maximum number of seconds before a cached value gets auto-refreshed.
    max_ttl: u64,

    /// Minimum number of seconds a value is cached for before being refreshed.
    min_ttl: u64,

    /// Maximum size of the pkarr packet cache in megabytes.
    cache_mb: u64,

    /// IP:port combination of the dns server regular ICANN queries should be forwarded to.
    forward_dns_server: SocketAddr,

    /// Maximum number of DHT queries one IP address can make per second.
    max_dht_queries_per_ip_per_second: Option<NonZeroU32>,

    /// Burst size of the rate limit.
    max_dht_queries_per_ip_burst: Option<NonZeroU32>,
}

impl ResolverSettings {
    pub fn default() -> Self {
        Self {
            max_ttl: 60 * 60 * 24, // 1 day
            min_ttl: 60 * 5,
            cache_mb: 100,
            forward_dns_server: "8.8.8.8:53"
                .parse()
                .expect("forward should be valid IP:Port combination."),
            max_dht_queries_per_ip_per_second: None,
            max_dht_queries_per_ip_burst: None
        }
    }
}

#[derive(thiserror::Error, Debug)]
enum PkarrResolverError {
    #[error("Failed to query the DHT with pkarr: {0}")]
    Dht(#[from] PkarrError),

    #[error("Failed to query the DHT with pkarr: {0}")]
    DnsSocket(#[from] DnsSocketError),
}

pub struct PkarrResolverBuilder {
    settings: ResolverSettings,
}

impl PkarrResolverBuilder {
    pub fn new() -> Self {
        Self {
            settings: ResolverSettings::default(),
        }
    }

    pub fn forward_server(mut self, socket: SocketAddr) -> Self {
        self.settings.forward_dns_server = socket;
        self
    }

    pub fn max_ttl(mut self, rate_s: u64) -> Self {
        self.settings.max_ttl = rate_s;
        self
    }

    pub fn min_ttl(mut self, rate_s: u64) -> Self {
        self.settings.min_ttl = rate_s;
        self
    }

    pub fn cache_mb(mut self, megabytes: u64) -> Self {
        self.settings.cache_mb = megabytes;
        self
    }

    /// Rate the number of DHT queries by ip addresses.
    pub fn max_dht_queries_per_ip_per_second(mut self, limit: Option<NonZeroU32>) -> Self {
        self.settings.max_dht_queries_per_ip_per_second = limit;
        self
    }

    /// Burst size of the rate limit.
    pub fn max_dht_queries_per_ip_burst(mut self, burst: Option<NonZeroU32>) -> Self {
        self.settings.max_dht_queries_per_ip_burst = burst;
        self
    }

    pub fn build_settings(self) -> ResolverSettings {
        self.settings
    }
}

/**
 * Pkarr resolver with cache.
 */
#[derive(Clone)]
pub struct PkarrResolver {
    client: PkarrClientAsync,
    cache: PkarrPacketLruCache,
    /**
     * Locks to use to update pkarr packets. This avoids concurrent updates.
     */
    lock_map: Arc<Mutex<HashMap<PublicKey, Arc<Mutex<()>>>>>,
    settings: ResolverSettings,
    rate_limiter: Arc<RateLimiter>,
}

impl PkarrResolver {
    /**
     * Resolves the DHT boostrap nodes with the forward server.
     */
    fn resolve_bootstrap_nodes(forward_dns_server: &SocketAddr) -> Vec<String> {
        tracing::debug!(
            "Connecting to the DNS forward server {}. Hold on...",
            forward_dns_server.to_string()
        );
        let addrs = MainlineBootstrapResolver::get_addrs(forward_dns_server);
        if addrs.is_err() {
            let err = addrs.unwrap_err();
            tracing::error!("{}", err);
            tracing::error!("Connecting to the DNS forward server failed. Couldn't resolve the DHT bootstrap nodes. Is the DNS forward server active?");
            panic!("Resolving bootstrap nodes failed. {}", err);
        }
        tracing::debug!("Success. DNS forward server reply received.");
        addrs.unwrap()
    }

    #[allow(dead_code)]
    pub async fn default() -> Self {
        Self::new(ResolverSettings::default()).await
    }

    pub fn builder() -> PkarrResolverBuilder {
        PkarrResolverBuilder::new()
    }

    pub async fn new(settings: ResolverSettings) -> Self {
        let addrs = Self::resolve_bootstrap_nodes(&settings.forward_dns_server);
        let mut dht_settings = DhtSettings::default();
        dht_settings.bootstrap = Some(addrs);
        let client = PkarrClient::builder()
            .minimum_ttl(0)
            .maximum_ttl(0) // Disable Pkarr caching
            .dht_settings(dht_settings) // Use resolved bootstrap node
            .resolvers(None)
            .build()
            .unwrap();
        let limiter = RateLimiterBuilder::new().max_per_second(settings.max_dht_queries_per_ip_per_second.clone());
        Self {
            client: client.as_async(),
            cache: PkarrPacketLruCache::new(Some(settings.cache_mb)),
            lock_map: Arc::new(Mutex::new(HashMap::new())),
            rate_limiter: Arc::new(limiter.build()),
            settings,
        }
    }

    fn is_refresh_needed(&self, item: &CacheItem) -> bool {
        let refresh_needed_in_s = item.next_refresh_needed_in_s(self.settings.min_ttl, self.settings.max_ttl);
        refresh_needed_in_s == 0
    }

    /**
     * Resolves a public key. Checks the cache first.
     */
    async fn resolve_pubkey_respect_cache(
        &mut self,
        pubkey: &PublicKey,
        from: Option<IpAddr>,
    ) -> Result<CacheItem, CustomHandlerError> {
        if let Some(cached) = self.cache.get(pubkey).await {
            let refresh_needed_in_s = cached.next_refresh_needed_in_s(self.settings.min_ttl, self.settings.max_ttl);

            if refresh_needed_in_s > 0 {
                tracing::trace!(
                    "Pkarr packet [{pubkey}] found in cache. Cache valid for {}s",
                    refresh_needed_in_s
                );
                return Ok(cached);
            }
        };

        if let Some(ip) = from {
            let is_rate_limited = self.rate_limiter.check_is_limited_and_increase(ip);
            if is_rate_limited {
                tracing::debug!("{ip} is rate limited from querying the DHT.");
                return Err(CustomHandlerError::RateLimited(ip));
            }
        }

        self.lookup_dht_and_cache(pubkey.clone())
            .await
            .map_err(|err| CustomHandlerError::Failed(err.into()))
    }

    /// Lookup DHT to pull pkarr packet. Will not check the cache first but store any new value in the cache. Returns cached value if lookup fails.
    async fn lookup_dht_and_cache(&mut self, pubkey: PublicKey) -> Result<CacheItem, PkarrResolverError> {
        tracing::info!("Before map mutex Lookup [{pubkey}] on the DHT.");
        let mut map_lock = self.lock_map.lock().await;
        let mutex = map_lock
            .entry(pubkey.clone())
            .or_insert_with(|| Arc::new(Mutex::new(())));
        tracing::info!("After map before key mutex Lookup [{pubkey}] on the DHT.");
        let _guard = mutex.lock().await;
        tracing::info!("After key mutex Lookup [{pubkey}] on the DHT.");

        if let Some(cache) = self.cache.get(&pubkey).await {
            if !self.is_refresh_needed(&cache) {
                // Value got updated in the meantime while aquiring the lock.
                tracing::info!("Refresh for [{pubkey}] not needed. Value got updated in the meantime.");
                return Ok(cache);
            }
        }

        tracing::info!("Lookup [{pubkey}] on the DHT.");
        let signed_packet = self.client.resolve(&pubkey).await?;
        tracing::info!("Finished lookup [{pubkey}] on the DHT.");
        if signed_packet.is_none() {
            tracing::debug!("DHT lookup for [{pubkey}] failed. Nothing found.");
            return Ok(self.cache.add_not_found(pubkey).await);
        };

        tracing::trace!("Refreshed cache for [{pubkey}].");
        let new_packet = signed_packet.unwrap();
        Ok(self.cache.add_packet(new_packet).await)
    }

    /**
     * Resolves a domain with pkarr.
     */
    pub async fn resolve(
        &mut self,
        query: &Vec<u8>,
        socket: &mut DnsSocket,
        from: Option<IpAddr>,
    ) -> std::prelude::v1::Result<Vec<u8>, CustomHandlerError> {
        // anydns validated the query before.
        let request = Packet::parse(query).expect("Unparsable query in pkarr_resolver.");
        let question = request.questions.first().expect("No question in query in pkarr_resolver.");
        let labels = question.qname.get_labels();

        tracing::debug!("New query: {} {:?} id={}", question.qname.to_string(), question.qtype, request.id());

        let tld = labels.last().expect("Question labels with no domain in pkarr_resolver").to_string();
        let parsed_option = parse_pkarr_uri(&tld);
        if let Err(e) = parsed_option {
            return match e {
                crate::pubkey_parser::PubkeyParserError::InvalidKey(_) => {
                    tracing::trace!("TLD .{tld} is not a pkarr key. Fallback to ICANN.");
                    Err(CustomHandlerError::Unhandled)
                },
                crate::pubkey_parser::PubkeyParserError::ValidButDifferent => {
                    tracing::trace!("TLD .{tld} is a pkarr key but its last bits are invalid.");
                    Ok(create_domain_not_found_reply(request.id()))
                },
            }
        }

        let pubkey = parsed_option.unwrap();

        match self.resolve_pubkey_respect_cache(&pubkey, from).await {
            Ok(item) => {
                if item.is_not_found() {
                    Ok(create_domain_not_found_reply(request.id()))
                } else {
                    let signed_packet = item.unwrap();
                    let packet = signed_packet.packet();
                    let reply = resolve_query(packet, &request, socket).await;
                    Ok(reply)
                }
            },
            Err(err) => Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::anydns::{EmptyHandler, HandlerHolder};
    use chrono::{DateTime, Utc};
    use pkarr::{
        dns::{Name, Packet, Question, ResourceRecord},
        Keypair, Settings, SignedPacket,
    };

    // use simple_dns::{Name, Question, Packet};
    use super::*;
    use std::net::Ipv4Addr;
    use zbase32;

    trait SignedPacketTimestamp {
        fn chrono_timestamp(&self) -> DateTime<Utc>;
    }

    impl SignedPacketTimestamp for SignedPacket {
        fn chrono_timestamp(&self) -> DateTime<Utc> {
            let timestamp = self.timestamp() / 1_000_000;
            let timestamp = DateTime::from_timestamp((timestamp as u32).into(), 0).unwrap();
            timestamp
        }
    }

    fn get_test_keypair() -> Keypair {
        // pk:cb7xxx6wtqr5d6yqudkt47drqswxk57dzy3h7qj3udym5puy9cso
        let secret = "6kfe1u5jyqxg644eqfgk1cp4w9yjzwq51rn11ftysuo6xkpc64by";
        let seed = zbase32::decode_full_bytes_str(secret).unwrap();
        let slice: &[u8; 32] = &seed[0..32].try_into().unwrap();
        let keypair = Keypair::from_secret_key(slice);
        keypair
    }

    async fn publish_record() {
        let keypair = get_test_keypair();
        // let uri = keypair.to_uri_string();
        // println!("Publish packet with pubkey {}", uri);

        let mut packet = Packet::new_reply(0);
        let ip: Ipv4Addr = "93.184.216.34".parse().unwrap();
        let record = ResourceRecord::new(
            Name::new("pknames.p2p").unwrap(),
            pkarr::dns::CLASS::IN,
            100,
            pkarr::dns::rdata::RData::A(ip.try_into().unwrap()),
        );
        packet.answers.push(record);
        let record = ResourceRecord::new(
            Name::new(".").unwrap(),
            pkarr::dns::CLASS::IN,
            100,
            pkarr::dns::rdata::RData::A(ip.try_into().unwrap()),
        );
        packet.answers.push(record);
        let signed_packet = SignedPacket::from_packet(&keypair, &packet).unwrap();

        let client = PkarrClient::new(Settings::default()).unwrap();
        let result = client.publish(&signed_packet);
        result.expect("Should have published.");
    }

    async fn get_dnssocket() -> DnsSocket {
        let handler = HandlerHolder::new(EmptyHandler::new());
        DnsSocket::new(
            "127.0.0.1:20384".parse().unwrap(),
            "8.8.8.8:53".parse().unwrap(),
            handler,
            None,
            None
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn query_domain() {
        publish_record().await;

        let keypair = get_test_keypair();
        let domain = format!("pknames.p2p.{}", keypair.to_z32());
        let name = Name::new(&domain).unwrap();
        let mut query = Packet::new_query(0);
        let question = Question::new(
            name.clone(),
            pkarr::dns::QTYPE::TYPE(pkarr::dns::TYPE::A),
            pkarr::dns::QCLASS::CLASS(pkarr::dns::CLASS::IN),
            true,
        );
        query.questions.push(question);

        let mut resolver = PkarrResolver::default().await;
        let mut socket = get_dnssocket().await;
        let result = resolver
            .resolve(&query.build_bytes_vec_compressed().unwrap(), &mut socket, None)
            .await;
        assert!(result.is_ok());
        let reply_bytes = result.unwrap();
        let reply = Packet::parse(&reply_bytes).unwrap();
        assert_eq!(reply.id(), query.id());
        assert_eq!(reply.answers.len(), 1);
        let answer = reply.answers.first().unwrap();
        assert_eq!(answer.name.to_string(), name.to_string());
        assert_eq!(answer.rdata.type_code(), pkarr::dns::TYPE::A);
    }

    #[tokio::test]
    async fn query_pubkey() {
        publish_record().await;

        let keypair = get_test_keypair();
        let domain = keypair.to_z32();
        let name = Name::new(&domain).unwrap();
        let mut query = Packet::new_query(0);
        let question = Question::new(
            name.clone(),
            pkarr::dns::QTYPE::TYPE(pkarr::dns::TYPE::A),
            pkarr::dns::QCLASS::CLASS(pkarr::dns::CLASS::IN),
            true,
        );
        query.questions.push(question);
        let mut resolver = PkarrResolver::default().await;
        let mut socket = get_dnssocket().await;
        let result = resolver
            .resolve(&query.build_bytes_vec_compressed().unwrap(), &mut socket, None)
            .await;
        assert!(result.is_ok());
        let reply_bytes = result.unwrap();
        let reply = Packet::parse(&reply_bytes).unwrap();
        assert_eq!(reply.id(), query.id());
        assert_eq!(reply.answers.len(), 1);
        let answer = reply.answers.first().unwrap();
        assert_eq!(answer.name.to_string(), name.to_string());
        assert_eq!(answer.rdata.type_code(), pkarr::dns::TYPE::A);
    }

    #[tokio::test]
    async fn query_invalid_pubkey() {
        let domain = "invalid_pubkey";
        let name = Name::new(&domain).unwrap();
        let mut query = Packet::new_query(0);
        let question = Question::new(
            name.clone(),
            pkarr::dns::QTYPE::TYPE(pkarr::dns::TYPE::A),
            pkarr::dns::QCLASS::CLASS(pkarr::dns::CLASS::IN),
            true,
        );
        query.questions.push(question);
        let mut resolver = PkarrResolver::default().await;
        let mut socket = get_dnssocket().await;
        let result = resolver
            .resolve(&query.build_bytes_vec_compressed().unwrap(), &mut socket, None)
            .await;
        assert!(result.is_err());
        // println!("{}", result.unwrap_err());
    }

    #[test]
    fn pkarr_parse() {
        let domain = "cb7xxx6wtqr5d6yqudkt47drqswxk57dzy3h7qj3udym5puy9cso";
        let decoded = zbase32::decode_full_bytes_str(domain);
        // assert!(decoded.is_err());
        let decoded = decoded.unwrap();
        println!("{:?}", decoded);
        if decoded.len() != 32 {
            println!("wrong length");
            return;
        }
        let trying: Result<PublicKey, _> = domain.try_into();
        assert!(trying.is_err());
    }

    #[tokio::test]
    async fn pkarr_invalid_packet1() {
        let pubkey = parse_pkarr_uri("7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy").unwrap();

        let mut resolver = PkarrResolver::default().await;
        let _result = resolver.resolve_pubkey_respect_cache(&pubkey, None).await;
        // assert!(result.is_some());
    }

    #[tokio::test]
    async fn pkarr_invalid_packet2() {
        let pubkey = parse_pkarr_uri("7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy").unwrap();
        let client = PkarrClient::new(Settings::default()).unwrap();
        let signed_packet = client.resolve(&pubkey).unwrap().unwrap();
        println!("Timestamp {}", signed_packet.chrono_timestamp());
        let reply_bytes = signed_packet.packet().build_bytes_vec_compressed().unwrap();
        Packet::parse(&reply_bytes).unwrap();
    }

    #[test]
    fn pkarr_invalid_packet3() {
        let keypair = Keypair::random();
        let pubkey_z32 = keypair.to_z32();

        // Construct reply with single CNAME record.
        let mut packet = Packet::new_reply(0);

        let name = Name::new("www.pknames.p2p").unwrap();
        let data = format!("pknames.p2p.{pubkey_z32}");
        let data = Name::new(&data).unwrap();
        let answer3 = ResourceRecord::new(
            name.clone(),
            simple_dns::CLASS::IN,
            100,
            simple_dns::rdata::RData::CNAME(simple_dns::rdata::CNAME(data)),
        );
        packet.answers.push(answer3);

        // Sign packet
        let signed_packet = SignedPacket::from_packet(&keypair, &packet).unwrap();

        // Serialize and parse again
        let reply_bytes = signed_packet.packet().build_bytes_vec().unwrap();
        Packet::parse(&reply_bytes).unwrap(); // Fail
    }
}
