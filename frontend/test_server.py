import urllib.request
r = urllib.request.urlopen("http://localhost:3000/")
print("HTTP:", r.getcode())
h = r.read().decode()
print("Has root div:", "id=\"root\"" in h)
print("Has script:", "main.tsx" in h)
