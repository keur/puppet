class ocf_dhcp {
  include ocf_dhcp::netboot

  # setup dhcp server
  package { 'isc-dhcp-server': }
  file {
    '/etc/dhcp/dhcpd.conf':
      source   => 'puppet:///modules/ocf_dhcp/dhcpd.conf',
      require  => [Package['isc-dhcp-server'], Exec['gen-desktop-leases']],
      notify   => Service['isc-dhcp-server'];

    '/usr/local/sbin/gen-desktop-leases':
      source => 'puppet:///modules/ocf_dhcp/gen-desktop-leases',
      mode   => '0755';
  }

  exec { 'gen-desktop-leases':
    command    => '/usr/local/sbin/gen-desktop-leases > /etc/dhcp/desktop-leases.conf',
    creates    => '/etc/dhcp/desktop-leases.conf',
    require    => [File['/usr/local/sbin/gen-desktop-leases'], Package['python3-ocflib']],
    notify     => Service['isc-dhcp-server'];
  }

  service { 'isc-dhcp-server':
    subscribe => File['/etc/dhcp/dhcpd.conf']
  }

  # send magic packet to wakeup desktops at lab opening time
  package { 'wakeonlan': }
  file {
    '/usr/local/bin/lab-wakeup':
      ensure  => link,
      links   => manage,
      target  => '/opt/share/utils/staff/lab/lab-wakeup',
      require => [Vcsrepo['/opt/share/utils'], Package['wakeonlan']];
  }

  cron {
    'lab-wakeup':
      command => '/usr/local/bin/lab-wakeup -q',
      minute  => '*/15',
      require => File['/usr/local/bin/lab-wakeup'];
  }

  # Firewall Rules #

  # Allow DNS
  ocf::firewall::firewall46 {
    '101 allow domain':
      opts => {
        chain  => 'PUPPET-INPUT',
        proto  => ['tcp', 'udp'],
        dport  => 53,
        action => 'accept',
      };
  }

  # Allow BOOTP (IPv4 only)
  firewall { '101 allow bootps':
    chain  => 'PUPPET-INPUT',
    proto  => 'udp',
    dport  => 67,
    action => 'accept',
  }

  # Allow TFTP
  ocf::firewall::firewall46 {
    '101 allow tftp':
      opts => {
        chain  => 'PUPPET-INPUT',
        proto  => 'udp',
        dport  => 69,
        action => 'accept',
      };
  }

  # Allow DHCP Server (IPv6 only)
  firewall { '101 allow dhcpv6-server':
    provider => 'ip6tables',
    chain    => 'PUPPET-INPUT',
    proto    => 'udp',
    dport    => 547,
    action   => 'accept',
  }
}
