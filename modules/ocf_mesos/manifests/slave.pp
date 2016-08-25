class ocf_mesos::slave {
  include ocf::packages::docker
  include ocf_mesos
  include ocf_mesos::package
  include ocf_mesos::slave::secrets

  augeas { '/etc/default/mesos-slave':
    lens    => 'Shellvars.lns',
    incl    => '/etc/default/mesos-slave',
    changes =>  [
      'set MASTER "zk://mesos0:2181,mesos1:2181,mesos2:2181/mesos"',
    ],
    notify  => Service['mesos-slave'],
    require => Package['mesos'];
  }


  $ocf_mesos_master_password = 'hunter2'
  $ocf_mesos_slave_password = 'hunter3'

  $file_defaults = {
    notify  => Service['mesos-slave'],
    require => Package['mesos'],
  }

  # TODO: when on Puppet 4, use per-expression defaults
  # https://docs.puppet.com/puppet/latest/reference/lang_resources_advanced.html#local-resource-defaults
  file {
    default:
      * => $file_defaults;

    '/opt/share/mesos/slave':
      ensure => directory;

    '/etc/mesos-slave':
      ensure  => directory,
      recurse => true,
      purge   => true;

    '/etc/mesos-slave/containerizers':
      content => "docker\n";

    # increase executor timeout in case we need to pull a Docker image
    '/etc/mesos-slave/executor_registration_timeout':
      content => "5mins\n";

    # remove old dockers as soon as we're done with them
    '/etc/mesos-slave/docker_remove_delay':
      content => "1secs\n";

    '/etc/mesos-slave/hostname':
      content => "${::hostname}\n";

    # Credentials needed to access the slave REST API.
    [
      '/etc/mesos-slave/authenticate_http_readonly',
      '/etc/mesos-slave/authenticate_http_readwrite',
    ]:
      content => "true\n";

    '/etc/mesos-slave/work_dir':
      content => "/var/lib/mesos-slave\n",
      require => File['/var/lib/mesos-slave'];

    '/var/lib/mesos-slave':
      ensure => directory;

    '/etc/mesos-slave/http_credentials':
      content => "/opt/share/mesos/slave/slave_credentials.json\n",
      require => File['/opt/share/mesos/slave/slave_credentials.json'];

    '/opt/share/mesos/slave/slave_credentials.json':
      content   => template('ocf_mesos/slave/mesos/slave_credentials.json.erb'),
      mode      => '0400',
      show_diff => false;

    # Credential to connect to the masters.
    '/etc/mesos-slave/credential':
      content => "/opt/share/mesos/slave/master_credential.json\n",
      require => File['/opt/share/mesos/slave/master_credential.json'];

    '/opt/share/mesos/slave/master_credential.json':
      content   => template('ocf_mesos/slave/mesos/master_credential.json.erb'),
      mode      => '0400',
      show_diff => false;
  }
}
