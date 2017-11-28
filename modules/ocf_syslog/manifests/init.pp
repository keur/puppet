class ocf_syslog {
  package { 'rsyslog': }

  service { 'rsyslog':
    require => [
      Package['rsyslog'],
      File['/etc/rsyslog.d/ocf.conf'],
    ],
  }

  ocf::firewall::firewall46 {
    '100 allow syslog on TCP':
      opts => {
        chain  => 'PUPPET-INPUT',
        proto  => 'tcp',
        dport  => '514',
        action => 'accept',
      };

    '101 allow syslog on UDP':
      opts => {
        chain  => 'PUPPET-INPUT',
        proto  => 'udp',
        dport  => '514',
        action => 'accept',
      };
  }

  file {
    '/var/log/remote':
      ensure => directory;

    '/etc/rsyslog.d/ocf.conf':
      source  => 'puppet:///modules/ocf_syslog/ocf.conf',
      notify  => Service['rsyslog'],
      require => Package['rsyslog'];

    '/etc/logrotate.d/ocf-syslog':
      source  => 'puppet:///modules/ocf_syslog/logrotate';
  }
}
