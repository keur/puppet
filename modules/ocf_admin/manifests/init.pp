class ocf_admin {
  include ocf::extrapackages
  include ocf::firewall::output_all
  include ocf::hostkeys
  include ocf::packages::cups
  include ocf::tmpfs
  include ocf_ocfweb::dev_config

  include ocf_admin::apt_dater
  include ocf_admin::create

  class { 'ocf::nfs':
    cron  => true,
    web   => true;
  }

  class { 'ocf::packages::docker':
    admin_group => 'ocfroot';
  }

  package {
    [
      'ipmitool',
      'wakeonlan',
    ]:;
  }

  file {
    '/opt/passwords':
      source => 'puppet:///private/passwords',
      group  => ocfroot,
      mode   => '0640';
    '/etc/ocfprinting.json':
      source => 'puppet:///private/ocfprinting.json',
      group  => ocfstaff,
      mode   => '0640';
  }

  # Firewall Rules #

  # Allow Redis
  firewall { '101 allow redis (IPv4)':
    chain    => 'PUPPET-INPUT',
    proto    => 'tcp',
    dport    => 6378,
    source => '169.229.226.1/24',
    action   => 'accept',
  }
  firewall { '101 allow redis (IPv6)':
    chain    => 'PUPPET-INPUT',
    provider => 'ip6tables',
    proto    => 'tcp',
    dport    => 6378,
    source   => '2607:f140:8801::1:1/96',
    action   => 'accept',
  }

  # Allow 8000-8999 for dev work
  ocf::firewall::firewall46 {
    '101 allow dev':
      opts => {
        chain  => 'PUPPET-INPUT',
        proto  => 'tcp',
        dport  => '8000-8999',
        action => 'accept',
      };
  }
}
