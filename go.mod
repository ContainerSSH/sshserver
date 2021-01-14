module github.com/containerssh/sshserver

go 1.14

require (
	github.com/containerssh/log v0.9.9
	github.com/containerssh/service v0.9.0
	github.com/containerssh/structutils v0.9.0
	github.com/containerssh/unixutils v0.9.0
	github.com/google/uuid v1.1.4
	github.com/stretchr/testify v1.7.0
	golang.org/x/crypto v0.0.0-20201221181555-eec23a3978ad
	golang.org/x/sys v0.0.0-20210113181707-4bcb84eeeb78 // indirect
)

replace (
	github.com/containerssh/log v0.9.2 => github.com/containerssh/log v0.9.9
	github.com/stretchr/testify v1.4.0 => github.com/stretchr/testify v1.6.1
	golang.org/x/crypto v0.0.0-20190308221718-c2843e01d9a2 => golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
	golang.org/x/crypto v0.0.0-20191011191535-87dc89f01550 => golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
	golang.org/x/net v0.0.0-20190404232315-eb5bcb51f2a3 => golang.org/x/net v0.0.0-20201110031124-69a78807bb2b
	golang.org/x/net v0.0.0-20190620200207-3b0461eec859 => golang.org/x/net v0.0.0-20201110031124-69a78807bb2b
	golang.org/x/sys v0.0.0-20180905080454-ebe1bf3edb33 => golang.org/x/sys v0.0.0-20200930185726-fdedc70b468f
	golang.org/x/sys v0.0.0-20190215142949-d0b11bdaac8a => golang.org/x/sys v0.0.0-20200930185726-fdedc70b468f
	golang.org/x/sys v0.0.0-20190412213103-97732733099d => golang.org/x/sys v0.0.0-20200930185726-fdedc70b468f
	golang.org/x/sys v0.0.0-20190916202348-b4ddaad3f8a3 => golang.org/x/sys v0.0.0-20200930185726-fdedc70b468f
	golang.org/x/sys v0.0.0-20191026070338-33540a1f6037 => golang.org/x/sys v0.0.0-20200930185726-fdedc70b468f
	golang.org/x/sys v0.0.0-20191224085550-c709ea063b76 => golang.org/x/sys v0.0.0-20200930185726-fdedc70b468f
	golang.org/x/sys v0.0.0-20200930185726-fdedc70b468f => golang.org/x/sys v0.0.0-20200930185726-fdedc70b468f
	golang.org/x/sys v0.0.0-20210113181707-4bcb84eeeb78 => golang.org/x/sys v0.0.0-20200930185726-fdedc70b468f
	gopkg.in/check.v1 v0.0.0-20161208181325-20d25e280405 => gopkg.in/check.v1 v1.0.0-20200227125254-8fa46927fb4f
)
