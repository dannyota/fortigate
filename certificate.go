package fortigate

import "context"

type apiLocalCertificate struct {
	Name                      string `json:"name"`
	Comments                  string `json:"comments"`
	State                     string `json:"state"`
	Range                     string `json:"range"`
	Source                    string `json:"source"`
	LastUpdated               int    `json:"last-updated"`
	EnrollProtocol            string `json:"enroll-protocol"`
	PrivateKeyRetain          string `json:"private-key-retain"`
	AutoRegenerateDays        int    `json:"auto-regenerate-days"`
	AutoRegenerateDaysWarning int    `json:"auto-regenerate-days-warning"`
	ACMEDomain                string `json:"acme-domain"`
	ACMEEmail                 string `json:"acme-email"`
}

type apiCACertificate struct {
	Name                  string `json:"name"`
	Range                 string `json:"range"`
	Source                string `json:"source"`
	SSLInspectionTrusted  string `json:"ssl-inspection-trusted"`
	SCEPURL               string `json:"scep-url"`
	AutoUpdateDays        int    `json:"auto-update-days"`
	AutoUpdateDaysWarning int    `json:"auto-update-days-warning"`
	SourceIP              string `json:"source-ip"`
	CAIdentifier          string `json:"ca-identifier"`
	LastUpdated           int    `json:"last-updated"`
	Obsolete              string `json:"obsolete"`
}

type apiCRLCertificate struct {
	Name     string `json:"name"`
	Source   string `json:"source"`
	Comment  string `json:"comment"`
	Comments string `json:"comments"`
}

type apiRemoteCertificate struct {
	Name     string `json:"name"`
	Source   string `json:"source"`
	Comment  string `json:"comment"`
	Comments string `json:"comments"`
}

// ListLocalCertificates retrieves local certificate metadata without certificate bodies.
// noinspection DuplicatedCode
func (c *Client) ListLocalCertificates(ctx context.Context, vdom string, opts ...ListOption) ([]LocalCertificate, error) {
	items, err := getVDOMPaged[apiLocalCertificate](ctx, c, vdom, "/api/v2/cmdb/vpn.certificate/local", opts)
	if err != nil {
		return nil, err
	}
	out := make([]LocalCertificate, len(items))
	for i, item := range items {
		out[i] = LocalCertificate{
			Name:                      item.Name,
			Comment:                   item.Comments,
			State:                     item.State,
			Range:                     item.Range,
			Source:                    item.Source,
			LastUpdated:               item.LastUpdated,
			EnrollProtocol:            item.EnrollProtocol,
			PrivateKeyRetain:          item.PrivateKeyRetain,
			AutoRegenerateDays:        item.AutoRegenerateDays,
			AutoRegenerateDaysWarning: item.AutoRegenerateDaysWarning,
			ACMEDomain:                item.ACMEDomain,
			ACMEEmail:                 item.ACMEEmail,
		}
	}
	return out, nil
}

// ListCACertificates retrieves CA certificate metadata without certificate bodies.
func (c *Client) ListCACertificates(ctx context.Context, vdom string, opts ...ListOption) ([]CACertificate, error) {
	items, err := getVDOMPaged[apiCACertificate](ctx, c, vdom, "/api/v2/cmdb/vpn.certificate/ca", opts)
	if err != nil {
		return nil, err
	}
	out := make([]CACertificate, len(items))
	for i, item := range items {
		out[i] = CACertificate(item)
	}
	return out, nil
}

// ListCRLCertificates retrieves certificate revocation list metadata.
func (c *Client) ListCRLCertificates(ctx context.Context, vdom string, opts ...ListOption) ([]CRLCertificate, error) {
	items, err := getVDOMPaged[apiCRLCertificate](ctx, c, vdom, "/api/v2/cmdb/vpn.certificate/crl", opts)
	if err != nil {
		return nil, err
	}
	out := make([]CRLCertificate, len(items))
	for i, item := range items {
		out[i] = CRLCertificate{Name: item.Name, Source: item.Source, Comment: coalesce(item.Comment, item.Comments)}
	}
	return out, nil
}

// ListRemoteCertificates retrieves remote certificate metadata without certificate bodies.
func (c *Client) ListRemoteCertificates(ctx context.Context, vdom string, opts ...ListOption) ([]RemoteCertificate, error) {
	items, err := getVDOMPaged[apiRemoteCertificate](ctx, c, vdom, "/api/v2/cmdb/vpn.certificate/remote", opts)
	if err != nil {
		return nil, err
	}
	out := make([]RemoteCertificate, len(items))
	for i, item := range items {
		out[i] = RemoteCertificate{Name: item.Name, Source: item.Source, Comment: coalesce(item.Comment, item.Comments)}
	}
	return out, nil
}
