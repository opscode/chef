require 'spec_helper'

describe Chef::Provider::Package::MicroDnf::MicroDnfHelper do
  let(:helper) { Chef::Provider::Package::MicroDnf::MicroDnfHelper.instance }

  it 'should return nil when querying for a package not installed on system' do
    allow(helper).to receive(:microdnf).with(
      ['repoquery', '--installed', 'notfound'],
    ).
      and_return(double(:stdout => ''))
    ver = helper.package_query(:whatinstalled, 'notfound')
    expect(ver).to be_a(Chef::Provider::Package::MicroDnf::Version)
    expect(ver.name).to eql('notfound')
    expect(ver.version).to eql(nil)
    expect(ver.arch).to eql(nil)
    expect(ver.to_s).to eql(nil)
  end

  it 'should return NVRA when querying an existing installed package' do
    allow(helper).to receive(:microdnf).with(
      ['repoquery', '--installed', 'tree'],
    ).
      and_return(double(:stdout => 'tree-1.7.0-0.3.i386'))
    ver = helper.package_query(:whatinstalled, 'tree')
    expect(ver).to be_a(Chef::Provider::Package::MicroDnf::Version)
    expect(ver.name).to eql('tree')
    expect(ver.version).to eql('0:1.7.0-0.3')
    expect(ver.arch).to eql('i386')
    expect(ver.to_s).to eql('tree-0:1.7.0-0.3.i386')
  end

  it 'should ignore metadata output when looking for a package in the repos' do
    allow(helper).to receive(:microdnf).with(
      [
        'repoquery',
        'nix2rpm-tree-1.8.0-4c1486j8g0czfpc7srk58wnbzl33xf9a',
      ],
    ).
      and_return(
        double(
          :stdout => "Downloading metadata...\n" +
            "Downloading metadata...\n" +
            "Downloading metadata...\n" +
            "nix2rpm-tree-1.8.0-4c1486j8g0czfpc7srk58wnbzl33xf9a-1-0.x86_64\n",
        ),
      )
    ver = helper.package_query(
      :whatavailable,
      'nix2rpm-tree-1.8.0-4c1486j8g0czfpc7srk58wnbzl33xf9a',
    )
    expect(ver).to be_a(Chef::Provider::Package::MicroDnf::Version)
    expect(ver.name).to eql(
      'nix2rpm-tree-1.8.0-4c1486j8g0czfpc7srk58wnbzl33xf9a',
    )
    expect(ver.version).to eql('0:1-0')
    expect(ver.arch).to eql('x86_64')
    expect(ver.to_s).to eql(
      'nix2rpm-tree-1.8.0-4c1486j8g0czfpc7srk58wnbzl33xf9a-0:1-0.x86_64',
    )
  end

  it 'should pass all options to microdnf' do
    allow(helper).to receive(:microdnf).with(
      [
        '--disablerepo=darwin-nix',
        'repoquery',
        'test-1.0.0-1.x86_64',
      ],
    ).
      and_return(double(:stdout => "test-1.0.0-1.x86_64\n"))
    ver = helper.package_query(
      :whatavailable,
      'test',
      :version => '1.0.0-1',
      :arch => 'x86_64',
      :options => ['--disablerepo=darwin-nix'],
    )
    expect(ver).to be_a(Chef::Provider::Package::MicroDnf::Version)
    expect(ver.name).to eql('test')
    expect(ver.version).to eql('0:1.0.0-1')
    expect(ver.arch).to eql('x86_64')
    expect(ver.to_s).to eql('test-0:1.0.0-1.x86_64')
  end

  it 'compares EVRAs correctly' do
    expect(helper.compare_versions('0:1.8.29-10.x86_64', '1.8.29-7')).
      to eql(-1)
    expect(helper.compare_versions('0:1.8.29-6.x86_64', '1.8.29-6')).
      to eql(0)
    expect(helper.compare_versions('0:1.8.29-6.x86_64', '1.8.29-7')).
      to eql(-1)
    expect(helper.compare_versions('0:1.8.29-6.x86_64', '1:1.8.29-4')).
      to eql(-1)
    expect(helper.compare_versions('0:1.8.29-6.el8.x86_64',
                                   '0:1.8.29-6.el8_3.1.x86_64')).to eql(-1)
  end
end

