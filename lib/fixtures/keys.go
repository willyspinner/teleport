package fixtures

var PEMBytes = map[string][]byte{
	"dsa": []byte(`-----BEGIN DSA PRIVATE KEY-----
MIIBuwIBAAKBgQD6PDSEyXiI9jfNs97WuM46MSDCYlOqWw80ajN16AohtBncs1YB
lHk//dQOvCYOsYaE+gNix2jtoRjwXhDsc25/IqQbU1ahb7mB8/rsaILRGIbA5WH3
EgFtJmXFovDz3if6F6TzvhFpHgJRmLYVR8cqsezL3hEZOvvs2iH7MorkxwIVAJHD
nD82+lxh2fb4PMsIiaXudAsBAoGAQRf7Q/iaPRn43ZquUhd6WwvirqUj+tkIu6eV
2nZWYmXLlqFQKEy4Tejl7Wkyzr2OSYvbXLzo7TNxLKoWor6ips0phYPPMyXld14r
juhT24CrhOzuLMhDduMDi032wDIZG4Y+K7ElU8Oufn8Sj5Wge8r6ANmmVgmFfynr
FhdYCngCgYEA3ucGJ93/Mx4q4eKRDxcWD3QzWyqpbRVRRV1Vmih9Ha/qC994nJFz
DQIdjxDIT2Rk2AGzMqFEB68Zc3O+Wcsmz5eWWzEwFxaTwOGWTyDqsDRLm3fD+QYj
nOwuxb0Kce+gWI8voWcqC9cyRm09jGzu2Ab3Bhtpg8JJ8L7gS3MRZK4CFEx4UAfY
Fmsr0W6fHB9nhS4/UXM8
-----END DSA PRIVATE KEY-----
`),
	"ecdsa": []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEINGWx0zo6fhJ/0EAfrPzVFyFC9s18lBt3cRoEDhS3ARooAoGCCqGSM49
AwEHoUQDQgAEi9Hdw6KvZcWxfg2IDhA7UkpDtzzt6ZqJXSsFdLd+Kx4S3Sx4cVO+
6/ZOXRnPmNAlLUqjShUsUBBngG0u2fqEqA==
-----END EC PRIVATE KEY-----
`),
	"rsa": []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBALdGZxkXDAjsYk10ihwU6Id2KeILz1TAJuoq4tOgDWxEEGeTrcld
r/ZwVaFzjWzxaf6zQIJbfaSEAhqD5yo72+sCAwEAAQJBAK8PEVU23Wj8mV0QjwcJ
tZ4GcTUYQL7cF4+ezTCE9a1NrGnCP2RuQkHEKxuTVrxXt+6OF15/1/fuXnxKjmJC
nxkCIQDaXvPPBi0c7vAxGwNY9726x01/dNbHCE0CBtcotobxpwIhANbbQbh3JHVW
2haQh4fAG5mhesZKAGcxTyv4mQ7uMSQdAiAj+4dzMpJWdSzQ+qGHlHMIBvVHLkqB
y2VdEyF7DPCZewIhAI7GOI/6LDIFOvtPo6Bj2nNmyQ1HU6k/LRtNIXi4c9NJAiAr
rrxx26itVhJmcvoUhOjwuzSlP2bE5VHAvkGB352YBg==
-----END RSA PRIVATE KEY-----
`),
	"rsa2": []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAz1MArBKUGR4pHEwGS8PC6buJcjY7IHd5E8N7bDezVlmkZhz3
2bMLCkKpoHGrcgL5UmiyTjcMZkfp/mVVkqGGQo+7ufiSbrUMgWhXpy0JL+ec2THY
9Q2LTF4VXE5Q1/3mc0yTxwm1DQsOMc5eysFDlOoztkkrTo1SFqxMIP/IB+UVs9pD
r3VUYCu+U5UFH0/5y7puR6BTc/kf6p1OR3cFN9hnyt0JAKewiHBpY8XVkBxTNU4z
WPyS2NPo4ir76XXVR0Y6oXnAewpngUVLbKOOQOy79au7+zQs/OQ11LhaiXoxDdSP
eFBeYeTUjej9YaBFKidV72W3SGOzcizu47+EUwIDAQABAoIBAHeDPojy8MKF+2bf
gGWehLaeL/5RusXdeUNmVbitZ0koxbdDjbDGIGAay5O80vsXMchKqDakTxaK8B2B
JtIvIKkwGCR9YVRGM95JWvX45SnjVyxxKsMguqMcPS4Hy1yndXgTtcBwHRlWvSkC
8Ovqet3WIFc9WKSgnKiLTBtdt16sq0OO0aF3yfb2tf5jT4KHKd18KFSvKO1oG7Ka
D57uj1wpB0CnFqPSCLx1FECG0PN8hPKipZInuzQv08bwIspTuBENTZESUs24KCye
y23seugGv//7gfv1QlXOuzBJLa4JPj6wg87z1u7b+OJit1xE8VU1LSh5a73G6xDU
NC/65EkCgYEA9E7THlhklAT5gRDfW99nCKCGWPMgfpQtbnC+c14Ef1owETcYENUU
zlcn8ZSAbgCFSJX4yRXdlvyuBzImw7N9ni94awysQxhZCF6brHF1yp2KhnznGd9+
PUP8ouictcbVCbkVFsH5c6xWWe4ojcdLDHCLlp/gIGF8C1q13H+aiVcCgYEA2T8R
GVEsjSnQKP39VZBkyDxeFy5aPVHK1PxO59yCoMov0CAAal09NuRvUzNC0c2+0K14
vrx9CSfPtwvUGLK3iIEhqawglnpJvIHCvYDZA8kaQipdCcLreT00I4i+zWqYVMCx
+8FJGdAev0PZHeUZmZxhA9rS90yxe0Z2n98NM2UCgYBGTHA/aRv3476PvvUmkJAr
UVWXPs543dZ80wBaXhFZO/Bc48ePAGFuRnH998dE3+16R31BD4OlsKu68llpMrrQ
y8QQuaLP46+q0t5krnlAhjiYHlS5gy/mHSwTDHAbdk1S8Oj6lXJcMJjgY8FTmqcj
uzbPbs2lQ6fX9JAkFKu5HQKBgQDMavaI7wPP1I9lcxFEyPi8HWmfwGLzHhqQbNVG
gQx9haKV4PbjHtbx5uMF089FIacyLnjWaP/ydH6US9IIZ2ohTPjC8g876NenRCZd
MHeDg2Bs7/XZsIrn6vo7kXmQSoQKA8O2E7rYSigUayBKa/+5thbnjKlEP+slBzmp
1zVRrQKBgHmGNSOpSuQiHRn9YuzZ/h5dX8jCLf+wHJzymCC1wVur8IxJjhhSuOIp
7JPquig/B6L2pNoxPa41VDGawQjJY5m4l3ap/oJj61HBB+Auf29BWXqg7V7B7XMB
NFJgTFxC2o3mVBkQ/s6FeDl62hpMheCuO6jRYbZjsM2tUeAKORws
-----END RSA PRIVATE KEY-----`),
	"user": []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEILYCAeq8f7V4vSSypRw7pxy8yz3V5W4qg8kSC3zJhqpQoAoGCCqGSM49
AwEHoUQDQgAEYcO2xNKiRUYOLEHM7VYAp57HNyKbOdYtHD83Z4hzNPVC4tM5mdGD
PLL8IEwvYu2wq+lpXfGQnNMbzYf9gspG0w==
-----END EC PRIVATE KEY-----
`),
}
