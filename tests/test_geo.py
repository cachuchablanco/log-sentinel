from log_sentinel.geo import haversine_km, lookup


def test_internal_rfc1918():
    geo = lookup("10.0.2.5")
    assert geo.internal is True
    assert geo.city == "San Francisco"


def test_specific_overrides_cidr():
    nyc = lookup("198.51.100.10")
    fra = lookup("198.51.100.77")
    assert nyc.city == "New York"
    assert fra.city == "Frankfurt"


def test_attacker_and_tokyo():
    assert lookup("203.0.113.50").city == "Moscow"
    assert lookup("203.0.113.80").city == "Tokyo"


def test_haversine_nyc_tokyo_is_long_haul():
    nyc = lookup("198.51.100.10")
    tky = lookup("203.0.113.80")
    km = haversine_km(nyc.lat, nyc.lon, tky.lat, tky.lon)
    assert 9000 < km < 12000
