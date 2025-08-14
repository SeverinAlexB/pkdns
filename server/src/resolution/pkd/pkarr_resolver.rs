use super::{pubkey_parser::parse_pkarr_uri, query_matcher::create_domain_not_found_reply};
use crate::{
    app_context::AppContext,
    config::TopLevelDomain,
    resolution::{dns_packets::ParsedQuery, DnsSocket, DnsSocketError, RateLimiter, RateLimiterBuilder},
};
use pkarr::{
    dns::{Name, Question, ResourceRecord},
    Client,
};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    num::NonZeroU32,
    sync::Arc,
};
use tokio::sync::Mutex;

use super::{
    bootstrap_nodes::MainlineBootstrapResolver,
    pkarr_cache::{CacheItem, PkarrPacketLruCache},
    query_matcher::resolve_query,
};
use pkarr::{
    dns::Packet,
    // mainline::dht::DhtSettings, Error as PkarrError, PkarrClient, PkarrClientAsync,
    PublicKey,
};

/// Errors that a CustomHandler can return.
#[derive(thiserror::Error, Debug)]
pub enum CustomHandlerError {
    /// Lookup failed. Error will be logged. SRVFAIL will be returned to the user.
    #[error(transparent)]
    Failed(#[from] Box<dyn std::error::Error + Send + Sync>),

    /// Handler does not consider itself responsible for this query.
    /// Will fallback to ICANN.
    #[error("Query is not processed by handler. Fallback to ICANN.")]
    Unhandled,

    /// Handler rate limited the IP. Will return RCODE::Refused.
    #[error("Source ip address {0} is rate limited.")]
    RateLimited(IpAddr),
}

#[derive(thiserror::Error, Debug)]
pub enum PkarrResolverError {
    // #[error("Failed to query the DHT with pkarr: {0}")]
    // Dht(#[from] PkarrError),
    #[error("Failed to query the DHT with pkarr: {0}")]
    DnsSocket(#[from] DnsSocketError),
}

/**
 * Pkarr resolver with cache.
 */
#[derive(Clone, Debug)]
pub struct PkarrResolver {
    client: Client,
    cache: PkarrPacketLruCache,
    /**
     * Locks to use to update pkarr packets. This avoids concurrent updates.
     */
    lock_map: Arc<Mutex<HashMap<PublicKey, Arc<Mutex<()>>>>>,
    context: AppContext,
    rate_limiter: Arc<RateLimiter>,
}

impl PkarrResolver {
    /**
     * Resolves the DHT boostrap nodes with the forward server.
     */
    fn resolve_bootstrap_nodes(forward_dns_server: &SocketAddr) -> Vec<SocketAddr> {
        tracing::debug!(
            "Connecting to the DNS forward server {}...",
            forward_dns_server.to_string()
        );

        let addrs = match MainlineBootstrapResolver::get_addrs(forward_dns_server) {
            Ok(addrs) => addrs,
            Err(err) => {
                tracing::error!("{}", err);
                tracing::error!("Connecting to the DNS forward server failed. Couldn't resolve the DHT bootstrap nodes. Is the DNS forward server active?");
                panic!("Resolving bootstrap nodes failed. {}", err);
            }
        };

        tracing::debug!("DHT bootstrap nodes resolved.");
        addrs
    }

    #[cfg(test)]
    pub async fn default() -> Self {
        let context = AppContext::test();
        Self::new(&context).await
    }

    pub async fn new(context: &AppContext) -> Self {
        let addrs = Self::resolve_bootstrap_nodes(&context.config.general.forward);
        let client = Client::builder()
            .minimum_ttl(0)
            .maximum_ttl(0) // Disable Pkarr caching
            .bootstrap(&addrs)
            .build()
            .unwrap();
        let limiter = RateLimiterBuilder::new().max_per_second(context.config.dht.dht_query_rate_limit);
        Self {
            client,
            cache: PkarrPacketLruCache::new(Some(context.config.dht.dht_cache_mb.into())),
            lock_map: Arc::new(Mutex::new(HashMap::new())),
            rate_limiter: Arc::new(limiter.build()),
            context: context.clone(),
        }
    }

    fn is_refresh_needed(&self, item: &CacheItem) -> bool {
        let refresh_needed_in_s =
            item.next_refresh_needed_in_s(self.context.config.dns.min_ttl, self.context.config.dns.max_ttl);
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
            if cached.public_key().to_string() == "7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy" {
                tracing::info!("7fmjp cached packet: {:?}", cached);
            }
            let refresh_needed_in_s =
                cached.next_refresh_needed_in_s(self.context.config.dns.min_ttl, self.context.config.dns.max_ttl);

            if refresh_needed_in_s > 0 {
                tracing::trace!(
                    "Pkarr packet [{pubkey}] found in cache. Cache valid for {}s",
                    refresh_needed_in_s
                );
                return Ok(cached);
            }
        };

        if let Some(ip) = from {
            let is_rate_limited = self.rate_limiter.check_is_limited_and_increase(&ip);
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
        let mut locked_map = self.lock_map.lock().await;
        let mutex = locked_map
            .entry(pubkey.clone())
            .or_insert_with(|| Arc::new(Mutex::new(())));
        let _guard = mutex.lock().await;

        if let Some(cache) = self.cache.get(&pubkey).await {
            if !self.is_refresh_needed(&cache) {
                // Value got updated in the meantime while aquiring the lock.
                tracing::trace!("Refresh for [{pubkey}] not needed. Value got updated in the meantime.");
                if cache.public_key().to_string() == "7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy" {
                    tracing::info!("7fmjp lookup_dht_and_cache cached packet: {:?}", cache);
                }
                return Ok(cache);
            }
        }

        tracing::trace!("Lookup [{pubkey}] on the DHT.");
        let signed_packet = self.client.resolve(&pubkey).await;
        if signed_packet.is_none() {
            tracing::debug!("DHT lookup for [{pubkey}] failed. Nothing found.");
            if pubkey.to_string() == "7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy" {
                tracing::info!("7fmjp  packet not found on the DHT");
            }
            return Ok(self.cache.add_not_found(pubkey).await);
        };

        tracing::trace!("Refreshed cache for [{pubkey}].");
        let new_packet = signed_packet.unwrap();
        if pubkey.to_string() == "7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy" {
            tracing::info!("7fmjp new packet found on the DHT: {:?}", new_packet);
        }
        Ok(self.cache.add_packet(new_packet).await)
    }

    fn remove_tld_if_necessary(&self, mut query: &mut Packet<'_>) -> bool {
        if let Some(tld) = &self.context.config.dht.top_level_domain {
            if tld.question_ends_with_pubkey_tld(query) {
                tld.remove(query);
                return true;
            }
        }
        false
    }

    fn add_tld_if_necessary(&self, mut reply: &mut Packet<'_>) -> bool {
        if let Some(tld) = &self.context.config.dht.top_level_domain {
            tld.add(reply);
            return true;
        }
        false
    }

    /**
     * Resolves a domain with pkarr.
     */
    pub async fn resolve(
        &mut self,
        query: &ParsedQuery,
        from: Option<IpAddr>,
    ) -> std::prelude::v1::Result<Vec<u8>, CustomHandlerError> {
        let mut request = query.packet.parsed().clone();
        let mut removed_tld = self.remove_tld_if_necessary(&mut request);
        if removed_tld {
            tracing::trace!("Removed tld from question: {:?}", request.questions.first().unwrap());
        }

        let question = request
            .questions
            .first()
            .expect("No question in query in pkarr_resolver.")
            .clone();
        let labels = question.qname.get_labels();
        let mut public_key = labels
            .last()
            .expect("Question labels with no domain in pkarr_resolver")
            .to_string();

        let parsed_option = parse_pkarr_uri(&public_key);
        if let Err(e) = parsed_option {
            return match e {
                super::pubkey_parser::PubkeyParserError::InvalidKey(_) => {
                    tracing::trace!("TLD .{public_key} is not a pkarr key. Fallback to ICANN.");
                    Err(CustomHandlerError::Unhandled)
                }
                super::pubkey_parser::PubkeyParserError::ValidButDifferent => {
                    tracing::trace!("TLD .{public_key} is a pkarr key but its last bits are invalid.");
                    Ok(create_domain_not_found_reply(request.id()))
                }
            };
        }

        let pubkey = parsed_option.unwrap();

        match self.resolve_pubkey_respect_cache(&pubkey, from).await {
            Ok(item) => {
                if item.not_found() {
                    return Ok(create_domain_not_found_reply(request.id()));
                };

                let signed_packet = item.unwrap();
                let mut packet = Packet::new_reply(0);
                for rr in signed_packet.all_resource_records() {
                    packet.answers.push(rr.clone());
                }
                let reply = resolve_query(&packet, &request).await;

                let reply = if removed_tld {
                    let mut packet = Packet::parse(&reply).unwrap();
                    self.add_tld_if_necessary(&mut packet);
                    packet.build_bytes_vec().unwrap()
                } else {
                    reply
                };
                Ok(reply)
            }
            Err(err) => Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};
    use pkarr::{
        dns::{Name, Packet, Question, ResourceRecord},
        Keypair, SignedPacket, Timestamp,
    };

    // use pkarr::dns::{Name, Question, Packet};
    use super::*;
    use std::net::Ipv4Addr;

    trait SignedPacketTimestamp {
        fn chrono_timestamp(&self) -> DateTime<Utc>;
    }

    impl SignedPacketTimestamp for SignedPacket {
        fn chrono_timestamp(&self) -> DateTime<Utc> {
            let timestamp = self.timestamp().as_u64() / 1_000_000;

            DateTime::from_timestamp((timestamp as u32).into(), 0).unwrap()
        }
    }

    fn get_test_keypair() -> Keypair {
        // pk:cb7xxx6wtqr5d6yqudkt47drqswxk57dzy3h7qj3udym5puy9cso
        let secret = "6kfe1u5jyqxg644eqfgk1cp4w9yjzwq51rn11ftysuo6xkpc64by";
        let seed = zbase32::decode_full_bytes_str(secret).unwrap();
        let slice: &[u8; 32] = &seed[0..32].try_into().unwrap();

        Keypair::from_secret_key(slice)
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
            pkarr::dns::rdata::RData::A(ip.into()),
        );
        packet.answers.push(record);
        let record = ResourceRecord::new(
            Name::new(".").unwrap(),
            pkarr::dns::CLASS::IN,
            100,
            pkarr::dns::rdata::RData::A(ip.into()),
        );
        packet.answers.push(record);
        let signed_packet = SignedPacket::new(&keypair, &packet.answers, Timestamp::now()).unwrap();

        let client = Client::builder().build().unwrap();
        let result = client.publish(&signed_packet, None).await;
        result.expect("Should have published.");
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
        let query = ParsedQuery::new(query.build_bytes_vec().unwrap()).unwrap();

        let mut resolver = PkarrResolver::default().await;
        let result = resolver.resolve(&query, None).await;
        assert!(result.is_ok());
        let reply_bytes = result.unwrap();
        let reply = Packet::parse(&reply_bytes).unwrap();
        assert_eq!(reply.id(), query.packet.id());
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
        let query = ParsedQuery::new(query.build_bytes_vec().unwrap()).unwrap();
        let mut resolver = PkarrResolver::default().await;
        let result = resolver.resolve(&query, None).await;
        assert!(result.is_ok());
        let reply_bytes = result.unwrap();
        let reply = Packet::parse(&reply_bytes).unwrap();
        assert_eq!(reply.id(), query.packet.id());
        assert_eq!(reply.answers.len(), 1);
        let answer = reply.answers.first().unwrap();
        assert_eq!(answer.name.to_string(), name.to_string());
        assert_eq!(answer.rdata.type_code(), pkarr::dns::TYPE::A);
    }

    #[tokio::test]
    async fn query_invalid_pubkey() {
        let domain = "invalid_pubkey";
        let name = Name::new(domain).unwrap();
        let mut query = Packet::new_query(0);
        let question = Question::new(
            name.clone(),
            pkarr::dns::QTYPE::TYPE(pkarr::dns::TYPE::A),
            pkarr::dns::QCLASS::CLASS(pkarr::dns::CLASS::IN),
            true,
        );
        query.questions.push(question);
        let query = ParsedQuery::new(query.build_bytes_vec().unwrap()).unwrap();
        let mut resolver = PkarrResolver::default().await;
        let result = resolver.resolve(&query, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn pkarr_invalid_packet1() {
        let pubkey = parse_pkarr_uri("7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy").unwrap();

        let mut resolver = PkarrResolver::default().await;
        let _result = resolver.resolve_pubkey_respect_cache(&pubkey, None).await;
        // assert!(result.is_some());
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
            pkarr::dns::CLASS::IN,
            100,
            pkarr::dns::rdata::RData::CNAME(pkarr::dns::rdata::CNAME(data)),
        );
        packet.answers.push(answer3);

        // Sign packet
        let signed_packet = SignedPacket::new(&keypair, &packet.answers, Timestamp::now()).unwrap();

        // Serialize and parse again
        let reply_bytes = signed_packet.encoded_packet();
        Packet::parse(&reply_bytes).unwrap(); // Fail
    }
}
