package tsnet

import (
	"testing"

	"github.com/sagernet/tailscale/net/tstun"
)

func TestResolvedDataPlaneMode(t *testing.T) {
	customTun := tstun.NewFake()
	tests := []struct {
		name    string
		server  Server
		want    DataPlaneMode
		wantErr bool
	}{
		{name: "auto userspace", server: Server{}, want: DataPlaneUserspace},
		{name: "auto custom tun", server: Server{Tun: customTun}, want: DataPlaneSystemServices},
		{name: "explicit userspace", server: Server{DataPlaneMode: DataPlaneUserspace}, want: DataPlaneUserspace},
		{name: "explicit system services", server: Server{Tun: customTun, DataPlaneMode: DataPlaneSystemServices}, want: DataPlaneSystemServices},
		{name: "explicit pure system", server: Server{Tun: customTun, DataPlaneMode: DataPlaneSystem}, want: DataPlaneSystem},
		{name: "userspace with custom tun", server: Server{Tun: customTun, DataPlaneMode: DataPlaneUserspace}, wantErr: true},
		{name: "system without custom tun", server: Server{DataPlaneMode: DataPlaneSystem}, wantErr: true},
		{name: "unknown", server: Server{DataPlaneMode: DataPlaneMode(255)}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := test.server.resolvedDataPlaneMode()
			if (err != nil) != test.wantErr {
				t.Fatalf("resolvedDataPlaneMode() error = %v, wantErr %v", err, test.wantErr)
			}
			if err == nil && got != test.want {
				t.Fatalf("resolvedDataPlaneMode() = %v, want %v", got, test.want)
			}
		})
	}
}
