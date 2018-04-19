class ocf_printhost::enforcer {
  package { ['cups-tea4cups', 'mariadb-client']: }

  file {
    '/etc/cups/tea4cups.conf':
      content => template('ocf_printhost/cups/tea4cups.conf.erb'),
      require => Package['cups-tea4cups'];

    '/usr/local/bin/enforcer':
      source  => 'puppet:///modules/ocf_printhost/enforcer',
      mode    => '0755';

    '/usr/local/bin/enforcer-pc':
      source  => 'puppet:///modules/ocf_printhost/enforcer-pc',
      mode    => '0755';

    '/opt/share/enforcer':
      ensure  => directory,
      mode    => '0500';

    '/opt/share/enforcer/enforcer.conf':
      source    => 'puppet:///private/enforcer/enforcer.conf',
      show_diff => false;

    '/opt/share/broker':
      ensure  => directory,
      mode    => '0500';

    '/opt/share/broker/broker.conf':
      content => template('ocf/broker.conf.erb'),
      mode    => '0400';
  }

  # We remove old document titles from the enforcer database for privacy reasons.
  cron { 'remove old document titles':
    command => 'mysql --defaults-file=/opt/share/enforcer-mysql.defaults < /opt/share/enforcer-remove-old-docs.sql',
    special => 'hourly',
  }

  file {
    '/opt/share/enforcer-remove-old-docs.sql':
      content => '
        UPDATE jobs
        SET doc_name = NULL
        WHERE time < DATE_SUB(NOW(), INTERVAL 14 DAY);
      ';

    '/opt/share/enforcer-mysql.defaults':
      source    => 'puppet:///private/enforcer-mysql.defaults',
      mode      => '0600',
      show_diff => false;
  }
}
