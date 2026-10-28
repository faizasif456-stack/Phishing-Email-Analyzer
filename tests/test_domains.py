import pytest

from phishscope.defang import defang, refang
from phishscope.domains import brand_in_text, impersonated_brand, org_domain, same_org


@pytest.mark.parametrize("host, expected", [
    ("mail.google.com", "google.com"),
    ("a.b.c.example.org", "example.org"),
    ("www.daraz.com.pk", "daraz.com.pk"),
    ("shop.bbc.co.uk", "bbc.co.uk"),
    ("example.com", "example.com"),
])
def test_org_domain(host, expected):
    assert org_domain(host) == expected


def test_same_org():
    assert same_org("mail.github.com", "github.com")
    assert not same_org("github.com", "github.io")
    assert not same_org("", "github.com")


@pytest.mark.parametrize("host, brand", [
    ("paypa1.com", "paypal"),
    ("paypal.com.account-verify.xyz", "paypal"),
    ("secure-microsoft-login.net", "microsoft"),
    ("rnicrosoft.com", "microsoft"),
    ("xn--pypal-4ve.com", "paypal"),
    ("app1e-id.com", "apple"),
])
def test_impersonation_detected(host, brand):
    assert impersonated_brand(host) == brand


@pytest.mark.parametrize("host", [
    "paypal.com", "www.paypal.com", "login.microsoftonline.com", "applebees.com",
    "github.com", "purchase-orders.com", "192.168.1.1",
])
def test_impersonation_not_flagged(host):
    assert impersonated_brand(host) is None


def test_brand_in_display_name():
    assert brand_in_text("PayPal Security") == "paypal"
    assert brand_in_text("Office 365 Admin") == "office365"
    assert brand_in_text("Wells  Fargo Alerts") == "wellsfargo"
    assert brand_in_text("Purchase Department") is None


def test_defang():
    assert defang("https://evil.example.com/a.b?c=d.e") == "hxxps://evil[.]example[.]com/a.b?c=d.e"
    assert defang("HTTP://x.io") == "hxxp://x[.]io"
    assert defang("bad@evil.com") == "bad[@]evil[.]com"
    assert defang("1.2.3.4") == "1[.]2[.]3[.]4"
    assert refang(defang("https://evil.example.com/x")) == "https://evil.example.com/x"
