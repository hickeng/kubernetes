package dynamiccertificates

// DynamicFileFilterContent provides a FilteredCertKeyContentProvider that can dynamically react to new file content
type DynamicFileFilterContent struct {
	*DynamicFileServingContent

	*FilterContent
}

var _ Notifier = &DynamicFileFilterContent{}
var _ FilterCertKeyContentProvider = &DynamicFileFilterContent{}
var _ ControllerRunner = &DynamicFileFilterContent{}

// NewDynamicFilterContentFromFiles returns a dynamic FilteredCertKeyContentProvider based on a cert and key filename and filter set.
func NewDynamicFilterContentFromFiles(purpose, certFile, keyFile string, filters map[string][]string, normalized string) (*DynamicFileFilterContent, error) {
	servingContent, err := NewDynamicServingContentFromFiles(purpose, certFile, keyFile)
	if err != nil {
		return nil, err
	}

	filterContent, err := NewFilterContent(filters, normalized)
	if err != nil {
		return nil, err
	}

	f := &DynamicFileFilterContent{
		DynamicFileServingContent: servingContent,
		FilterContent:             filterContent,
	}

	if err := f.loadServingCert(); err != nil {
		return nil, err
	}

	return f, nil
}
