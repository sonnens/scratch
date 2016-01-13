import sys
from Registry import Registry

reg = Registry.Registry(sys.argv[1])

def rec(key, depth=0):
	print "\t" * depth + key.path()
	for value in [v for v in key.values() if v.value_type() == Registry.RegSZ or v.value_type() == Registry.RegExpandSZ or v.value_type() == Registry.RegBin or v.value_type() == Registry.RegDWord]:
		if value.value_type() == Registry.RegDWord:
			print "\t" * (depth+1) + "* %s: dword=%08x" % (value.name(), value.value())
		elif value.value_type() == Registry.RegBin:
			s = " ".join(["%02x" % (ord(c)) for c in value.value()])
			print "\t" * (depth+1) + "* %s: hex(%s)" % (value.name(), s)
		else:
			print "\t" * (depth+1) + "* %s: %s" % (value.name(), value.value())
	for subkey in key.subkeys():
		rec(subkey, depth + 1)

key = reg.open(sys.argv[2])
rec(key)
