package fortigate

import (
	"context"
	"testing"
)

func TestCertificates(t *testing.T) {
	client := newTestClient(t, map[string]string{
		"/api/v2/cmdb/vpn.certificate/local": `[
			{
				"name": "local-cert",
				"comments": "local certificate",
				"state": "OK",
				"range": "global",
				"source": "factory",
				"last-updated": 1700000000,
				"enroll-protocol": "none",
				"private-key-retain": "enable",
				"auto-regenerate-days": 0,
				"auto-regenerate-days-warning": 0,
				"acme-domain": "vpn.example.test",
				"acme-email": "admin@example.test"
			}
		]`,
		"/api/v2/cmdb/vpn.certificate/ca": `[
			{
				"name": "ca-cert",
				"range": "global",
				"source": "factory",
				"ssl-inspection-trusted": "enable",
				"scep-url": "",
				"auto-update-days": 0,
				"auto-update-days-warning": 0,
				"source-ip": "192.0.2.10",
				"ca-identifier": "ca-id",
				"last-updated": 1700000001,
				"obsolete": "disable"
			}
		]`,
		"/api/v2/cmdb/vpn.certificate/crl": `[
			{"name": "crl1", "source": "upload", "comments": "crl"}
		]`,
		"/api/v2/cmdb/vpn.certificate/remote": `[
			{"name": "remote1", "source": "upload", "comments": "remote"}
		]`,
	})

	local, err := client.ListLocalCertificates(context.Background(), "root")
	if err != nil {
		t.Fatal(err)
	}
	if len(local) != 1 || local[0].Name != "local-cert" || local[0].ACMEDomain != "vpn.example.test" {
		t.Errorf("local = %#v", local)
	}

	ca, err := client.ListCACertificates(context.Background(), "root")
	if err != nil {
		t.Fatal(err)
	}
	if len(ca) != 1 || ca[0].SSLInspectionTrusted != "enable" || ca[0].CAIdentifier != "ca-id" {
		t.Errorf("ca = %#v", ca)
	}

	crl, err := client.ListCRLCertificates(context.Background(), "root")
	if err != nil {
		t.Fatal(err)
	}
	if len(crl) != 1 || crl[0].Comment != "crl" {
		t.Errorf("crl = %#v", crl)
	}

	remote, err := client.ListRemoteCertificates(context.Background(), "root")
	if err != nil {
		t.Fatal(err)
	}
	if len(remote) != 1 || remote[0].Comment != "remote" {
		t.Errorf("remote = %#v", remote)
	}
}
