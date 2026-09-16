from pathlib import Path
import sys
for root in sys.argv[1:]:
    p = Path(root)/'util/linuxfw/magicsock_cgnat_integration_test.go'
    s = p.read_text()
    s = s.replace(' "bytes"\n', ' "bytes"\n "errors"\n\n "github.com/coreos/go-iptables/iptables"\n')
    old = ' if os.Geteuid() != 0 { t.Fatal("requires root in disposable namespace") }'
    assert old in s
    s = s.replace(old, old + '''
 // Upstream unit tests replace this process-global predicate with a fake
 // string matcher. Use the real classifier only for this isolated kernel test.
 oldClassifier := isNotExistError
 isNotExistError = func(err error) bool {
  var iptErr *iptables.Error
  return errors.As(err, &iptErr) && iptErr.IsNotExist()
 }
 t.Cleanup(func() { isNotExistError = oldClassifier })
''')
    p.write_text(s)
