(function () {
  function parseQuery() {
    const params = new URLSearchParams(location.search);
    const domain = decodeURIComponent(params.get('domain') || '');
    const src = decodeURIComponent(params.get('src') || '');
    let reasons = [];
    try {
      const r = params.get('reasons');
      if (r) reasons = JSON.parse(decodeURIComponent(r));
    } catch {
      reasons = [];
    }
    return { domain, src, reasons };
  }

  function humanizeReason(reason) {
    switch (reason) {
      case 'brand_mismatch':
        return 'Microsoft 365 login UI detected on a non-Microsoft domain';
      case 'url_m365_oidc_pattern':
        return 'Microsoft identity (OIDC) URL pattern observed on this domain';
      case 'aad_cookie_on_non_ms_domain':
        return 'Azure AD authentication cookie set by this non-Microsoft domain';
      case 'ms_headers_on_non_ms_origin':
        return 'Response contained Microsoft-specific headers on this domain';
      case 'csp_references_ms_on_non_ms_origin':
        return 'Content Security Policy references Microsoft login/CDN on this domain';
      default:
        return reason;
    }
  }

  function render() {
    const { domain, reasons } = parseQuery();
    const domainEl = document.getElementById('domain');
    const listEl = document.getElementById('reasons');
    if (domainEl) domainEl.textContent = domain || '(unknown)';
    if (listEl) {
      listEl.innerHTML = '';
      (reasons || []).forEach((r) => {
        const li = document.createElement('li');
        li.textContent = humanizeReason(r);
        listEl.appendChild(li);
      });
    }
  }

  render();
})();


