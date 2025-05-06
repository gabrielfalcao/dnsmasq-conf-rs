use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::str::FromStr;

use dnsmasq_conf_rs::{ConfFormat, Config, ConfigAttribute, Error, Result};
use hickory_proto::rr::Name;
use iocore_test::folder_path;
use k9::assert_equal;

#[test]
fn test_config_attributes() -> Result<()> {
    let attributes = match ConfFormat::parse_into_config_attributes(
        &folder_path!().join("example.conf").read()?,
    ) {
        Ok(attributes) => attributes,
        Err(e) => {
            eprintln!("{}", e.to_string());
            return Err(Error::ParseError(e.to_string()));
        },
    };

    assert_equal!(
        attributes,
        vec![
            ConfigAttribute::Boolean("bogus-priv".to_string()),
            ConfigAttribute::CacheSize(1000000),
            ConfigAttribute::ConfPath("./block.conf".to_string()),
            ConfigAttribute::ConfPath("./map.conf".to_string()),
            ConfigAttribute::Boolean("domain-needed".to_string()),
            ConfigAttribute::Boolean("expand-hosts".to_string()),
            ConfigAttribute::Boolean("log-queries".to_string()),
            ConfigAttribute::Boolean("log-debug".to_string()),
            ConfigAttribute::LogFacility("/var/log/dnsmasq.log".to_string()),
            ConfigAttribute::Server(Ipv4Addr::from_str("1.1.1.1").unwrap()),
            ConfigAttribute::Server(Ipv4Addr::from_str("8.8.8.8").unwrap()),
            ConfigAttribute::Boolean("strict-order".to_string()),
            ConfigAttribute::AddressWithIpv4(
                Name::from_str("one.one.one").unwrap(),
                Ipv4Addr::from_str("1.1.1.1").unwrap()
            ),
            ConfigAttribute::AddressName(Name::from_str("block.it").unwrap()),
        ]
    );
    Ok(())
}

#[test]
fn test_load_config_simple() -> Result<()> {
    let block_config_path = folder_path!().join("block.conf");
    let config = match Config::from_path(&block_config_path) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("{}", e.to_string());
            return Err(Error::ParseError(e.to_string()));
        },
    };

    let mut expected_config = Config::new(&block_config_path);
    expected_config.conf_file.push("sub-block.conf".to_string());
    expected_config.address.push((Name::from_str("*.test.com").unwrap(), None));
    assert_equal!(config, expected_config);
    Ok(())
}

#[test]
fn test_load_config_with_sub_confs() -> Result<()> {
    let example_config_path = folder_path!().join("example.conf");
    let config = match Config::from_path(&example_config_path) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("{}", e.to_string());
            return Err(Error::ParseError(e.to_string()));
        },
    };

    let expected_config = Config {
        path: example_config_path.clone(),
        conf_file: vec!["./block.conf".to_string(), "./map.conf".to_string()],
        server: vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)],
        strict_order: true,
        domain_needed: true,
        expand_hosts: true,
        log_queries: true,
        log_debug: true,
        bogus_priv: true,
        log_facility: Some("/var/log/dnsmasq.log".to_string()),
        address: vec![
            (Name::from_str("one.one.one").unwrap(), Some(Ipv4Addr::new(1, 1, 1, 1))),
            (Name::from_str("block.it").unwrap(), None),
        ],
        key_value: BTreeMap::new(),
        port: None,
        min_port: None,
        max_port: None,
        edns_packet_max: None,
        port_limit: None,
        cache_size: Some(1000000),
        except_interface: None,
        listen_address: None,
        auth_server: None,
    };
    assert_equal!(config, expected_config);
    let expected_unified_config = Config {
        path: example_config_path.clone(),
        conf_file: Vec::new(),
        server: vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)],
        strict_order: true,
        domain_needed: true,
        expand_hosts: true,
        log_queries: true,
        log_debug: true,
        bogus_priv: true,
        log_facility: Some("/var/log/dnsmasq.log".to_string()),
        address: vec![
            (Name::from_str("one.one.one").unwrap(), Some(Ipv4Addr::new(1, 1, 1, 1))),
            (Name::from_str("block.it").unwrap(), None),
            (Name::from_str("*.test.com").unwrap(), None),
            (Name::from_str("github.com").unwrap(), Some(Ipv4Addr::new(20, 201, 28, 151))),
            (Name::from_str("*.test.sub").unwrap(), None),
        ],
        key_value: BTreeMap::new(),
        port: None,
        min_port: None,
        max_port: None,
        edns_packet_max: None,
        port_limit: None,
        cache_size: Some(1000000),
        except_interface: None,
        listen_address: None,
        auth_server: None,
    };
    assert_equal!(config.unify()?, expected_unified_config);
    Ok(())
}
