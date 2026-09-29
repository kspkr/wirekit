package httpkit

import (
	"errors"
	"net/url"
	"reflect"
	"testing"
)

func TestParseQuery(t *testing.T) {
	cases := []struct {
		in      string
		want    Params
		wantErr bool
	}{
		{"", nil, false},
		{"?", nil, false},
		{"a=1", Params{{"a", "1"}}, false},
		{"?a=1&b=2", Params{{"a", "1"}, {"b", "2"}}, false},
		{"b=2&a=1&b=3", Params{{"b", "2"}, {"a", "1"}, {"b", "3"}}, false},
		{"a", Params{{"a", ""}}, false},
		{"a=", Params{{"a", ""}}, false},
		{"=v", Params{{"", "v"}}, false},
		{"&&a=1&&", Params{{"a", "1"}}, false},
		{"q=hello+world&x=a%20b", Params{{"q", "hello world"}, {"x", "a b"}}, false},
		{"k%3Dey=v%26al", Params{{"k=ey", "v&al"}}, false},
		{"a=b=c", Params{{"a", "b=c"}}, false},
		{"a=1;b=2", Params{{"a", "1;b=2"}}, false},
		{"bad=%zz&ok=1", Params{{"bad", "%zz"}, {"ok", "1"}}, true},
		{"%zz=1", Params{{"%zz", "1"}}, true},
		{"u=%E2%9C%93", Params{{"u", "✓"}}, false},
	}
	for _, c := range cases {
		got, err := ParseQuery(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("ParseQuery(%q) err = %v, wantErr %v", c.in, err, c.wantErr)
		}
		if err != nil && !errors.Is(err, ErrMalformed) {
			t.Errorf("ParseQuery(%q) err does not wrap ErrMalformed: %v", c.in, err)
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("ParseQuery(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestParamsAccessors(t *testing.T) {
	ps, _ := ParseQuery("a=1&b=2&a=3")
	if ps.Get("a") != "1" || ps.Get("b") != "2" || ps.Get("c") != "" {
		t.Error("Get wrong")
	}
	if v, ok := ps.Lookup("b"); !ok || v != "2" {
		t.Error("Lookup wrong")
	}
	if _, ok := ps.Lookup("c"); ok {
		t.Error("Lookup(c) present")
	}
	if !ps.Has("a") || ps.Has("A") { // case-sensitive
		t.Error("Has wrong")
	}
	if got := ps.Values("a"); !reflect.DeepEqual(got, []string{"1", "3"}) {
		t.Errorf("Values = %v", got)
	}
	if ps.Values("zzz") != nil {
		t.Error("Values(missing) != nil")
	}

	ps.Set("a", "x")
	if !reflect.DeepEqual(ps, Params{{"a", "x"}, {"b", "2"}}) {
		t.Errorf("after Set = %v", ps)
	}
	ps.Set("c", "3")
	ps.Add("d", "4")
	if !reflect.DeepEqual(ps, Params{{"a", "x"}, {"b", "2"}, {"c", "3"}, {"d", "4"}}) {
		t.Errorf("after Set/Add = %v", ps)
	}
	if !ps.Del("b") || ps.Del("b") || ps.Has("b") {
		t.Error("Del wrong")
	}
	c := ps.Clone()
	c[0].Value = "changed"
	if ps[0].Value == "changed" {
		t.Error("Clone shares storage")
	}
	var nilPs Params
	if nilPs.Clone() != nil {
		t.Error("Clone(nil) != nil")
	}
}

func TestParamsEncode(t *testing.T) {
	ps := Params{{"q", "hello world"}, {"k=ey", "v&al"}, {"empty", ""}, {"u", "✓"}}
	enc := ps.Encode()
	if enc != "q=hello+world&k%3Dey=v%26al&empty=&u=%E2%9C%93" {
		t.Errorf("Encode = %q", enc)
	}
	back, err := ParseQuery(enc)
	if err != nil || !reflect.DeepEqual(back, ps) {
		t.Errorf("round trip = %v, %v", back, err)
	}
	if (Params{}).Encode() != "" {
		t.Error("Encode(empty) not empty")
	}
	std := ps.ToStd()
	want := url.Values{"q": {"hello world"}, "k=ey": {"v&al"}, "empty": {""}, "u": {"✓"}}
	if !reflect.DeepEqual(std, want) {
		t.Errorf("ToStd = %v", std)
	}
}

func FuzzParseQuery(f *testing.F) {
	f.Add("a=1&b=2")
	f.Add("%zz=%zz&&=")
	f.Fuzz(func(t *testing.T, s string) {
		ps, err := ParseQuery(s)
		if err != nil {
			return
		}
		// A cleanly parsed query must survive an encode/parse round trip.
		back, err := ParseQuery(ps.Encode())
		if err != nil {
			t.Fatalf("re-parse failed: %v", err)
		}
		if !reflect.DeepEqual(back, ps) && (len(back) != 0 || len(ps) != 0) {
			t.Fatalf("round trip changed params: %v -> %v", ps, back)
		}
	})
}

func BenchmarkParseQuery(b *testing.B) {
	q := "q=wirekit+go&hl=en&source=hp&ei=abcdefghijklmnop&iflsig=AOEireoAAAAAZ&ved=0ahUKEwj&uact=5&oq=wirekit&gs_lp=Egdnd3Mtd2l6IgdgZ29sYW5nMgUQABiABDIFEAAYgAQ"
	b.ReportAllocs()
	for b.Loop() {
		if _, err := ParseQuery(q); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParamsEncode(b *testing.B) {
	ps, _ := ParseQuery("q=wirekit+go&hl=en&source=hp&ei=abcdefghijklmnop&uact=5&oq=wirekit")
	b.ReportAllocs()
	for b.Loop() {
		ps.Encode()
	}
}
