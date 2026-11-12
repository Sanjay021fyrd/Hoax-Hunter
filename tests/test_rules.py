from src.rules import analyze_rules, find_urls, is_official_url


def ids(text):
    return {f.id for f in analyze_rules(text).flags}


def test_asking_to_share_otp_is_critical():
    result = analyze_rules("Share the OTP sent to you right now to secure your funds.")
    assert "credential_request" in {f.id for f in result.flags}
    assert result.critical


def test_warning_not_to_share_otp_is_not_a_request():
    for text in (
        "Your OTP is 482913. Do not share it with anyone.",
        "Never share your OTP with anybody. -HDFC Bank",
        "Please don't share your PIN with anyone.",
    ):
        assert "credential_request" not in ids(text), text
        assert not analyze_rules(text).critical, text


def test_lookalike_bank_domain_is_critical():
    result = analyze_rules("Update KYC now: http://sbi-kyc-update.xyz/login")
    assert "lookalike_domain" in {f.id for f in result.flags}
    assert "suspicious_domain" in {f.id for f in result.flags}
    assert result.critical


def test_real_bank_domain_is_not_flagged_as_link():
    text = "View your statement at hdfcbank.com or on the app."
    assert not {"has_link", "lookalike_domain", "suspicious_domain"} & ids(text)


def test_brand_prefix_trick_is_caught():
    # real brand name appears first, but the registered domain is different
    assert "lookalike_domain" in ids("Login: paytm.com.verify-now.xyz/kyc")


def test_url_shortener_and_raw_ip():
    assert "shortened_link" in ids("Click bit.ly/3abcXYZ now")
    assert "ip_link" in ids("Open http://192.168.10.5/login to continue")


def test_plain_text_is_not_mistaken_for_a_link():
    assert (
        find_urls("Ok lar... Joking wif u oni... see u at 5.30pm e.g. tomorrow") == []
    )
    assert find_urls("mail me at someone@gmail.com") == []


def test_trailing_punctuation_is_not_part_of_the_url():
    [(url, start, end)] = find_urls("Visit https://example.com/pay.")
    assert url == "https://example.com/pay"


def test_is_official_url():
    assert is_official_url("https://www.incometax.gov.in/refund")
    assert is_official_url("amazon.in/orders")
    assert not is_official_url("amazon-refund.top")


def test_ordinary_chat_has_no_flags():
    result = analyze_rules("Hey, are we still meeting for lunch tomorrow at 1?")
    assert result.score == 0
    assert result.flags == ()


def test_score_is_capped_at_100_and_flags_sorted_by_weight():
    text = (
        "URGENT!! Dear customer your SBI account will be blocked today. Share your OTP "
        "and pay Rs 500 processing fee at http://sbi-kyc.xyz to claim your lottery prize"
    )
    result = analyze_rules(text)
    assert result.score == 100
    weights = [f.weight for f in result.flags]
    assert weights == sorted(weights, reverse=True)


def test_spans_point_at_the_evidence():
    text = "Hurry, claim your prize at http://win-big.xyz"
    for flag in analyze_rules(text).flags:
        for start, end in flag.spans:
            assert 0 <= start < end <= len(text)


def test_empty_text():
    assert analyze_rules("").score == 0


def test_offering_your_own_details_is_not_a_request():
    # found by scanning thousands of real genuine messages
    for text in (
        "Great. So should i send you my account number.",
        "I will share my password with you tonight",
    ):
        assert not analyze_rules(text).critical, text


def test_asking_for_someone_elses_details_is_still_critical():
    for text in (
        "Send me your id and password",
        "Please share your account number and PIN",
    ):
        assert analyze_rules(text).critical, text
