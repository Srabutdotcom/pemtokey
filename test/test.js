//import { pem2key } from "../src/pem2key.js"
import { pem2key } from "../dist/pem2key.js"

//*PKCS1
const RSAPrivateKeyPem = `-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu
KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIJLixBy2qpFoS4DSmoEm
o3qGy0t6z09AIJtH+5OeRV1be+N4cDYJKffGzDa88vQENZiRm0GRq6a+HPGQMd2k
TQIhAKMSvzIBnni7ot/OSie2TmJLY4SwTQAevXysE2RbFDYdAiEBCUEaRQnMnbp7
9mxDXDf6AU0cN/RPBjb9qSHDcWZHGzUCIG2Es59z8ugGrDY+pxLQnwfotadxd+Uy
v/Ow5T0q5gIJAiEAyS4RaI9YG8EWx/2w0T67ZUVAw8eOMB6BIUg0Xcu+3okCIBOs
/5OiPgoTdSy7bcF9IGpSE8ZgGKzgYQVZeN97YE00
-----END RSA PRIVATE KEY-----`

const PrivateKeyPem = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCoknaik3X9AwXf
1nb/BfHlR4RBcij+Ri2RzxZfdcTuhcIL4XLrgwaz/Skx3R/UjU3eoxneBjcGeA7X
QX75aXMS2FKrfQEJ6mp9AVQTowPC5VkAp8L8vk/cBrckZFHQsm9bHnLirJ6LYhWK
sLbvgpJo+P4OMG4P/GeQVwaWwLxaZNSs0sEjVRuy0vbWCO4jJwnmZpPMxU0sRCRN
xod3n6DJ0XhwCP/CxhlFVHjoM/nX/HGlPWkwG05BFBH4J9Zy4SNNNg6CDjIsl56R
2Fu8d/RHtIB/UPhIEoV6t5rWkJx4SP76OwjiXl9IGiDWpb6uu2/OQctZRBezxvCZ
O4lgzKFXAgMBAAECggEAYK4XsmhmbCTWsqka+GqdcIVS2gIydpsjOZQO3dL6jl5S
i2PS+DXem04f2URcJBiix4S9qjPgTSqAQH6E52DOKcm9qDL6bIhwaJ9hbB27Y4UM
Ra7xyukPfj6vvQR4U/xyl0zgURb1mzU266MsWDOH6wKbGuI1zZ9SelsfIUkK/cAV
s6Ao4kzCCQWZMQ/GkYxtQXg/tdPtI2Ueexon0Xtr4bc50XefEFvpKNi3ZqX7fRHV
e2bvnzKH6TN6DlEBruIdRwLsfmFXMIXU98D1OYokaaeVeHH5iZ2nXrlGGw72RfcQ
awrEHvMTTUhzg5LnMw30Smq1ogPanhLtbofPqIQJwQKBgQDfxKZ7lFle+tiMEKmU
87uiRavAHrmQNipqBcbtadJqqQtvGOCxwSg9phh2YnwxRSyw1oBpg4ogvg1QbhqV
UNfB8b/M2kpPRpGZpjCvi6En8GzK6K4e/UQJ4i0l7tPT9tt3TynbMwb3xFcEnFEX
IxfcWnlbC5tm5Sea6b4BzwK84QKBgQDA2nvqHNsqU9HyCX61R5Bo2QLnsI4CgUBk
z2hhc4bteb//mKCWeVvPNRu9AFhNEJzix0/EEkCVhbpIKE1DUCzBPWI/4CkH1bRc
RBE7/7I3pcMBbV22OdGoISmUf6IFZSyQuBoShLDBH3CVmqdmto9b5nwYaTgdycvt
xpyQvdKtNwKBgHFzF2EyXnlcPqwMyp29URU9s41NRpGKFMj6MtgtvcPb/vMNruYQ
Y2GWM3LaDdNBGh5yMlrMmRxunvt3Rz0K5sjq025+AgzdX3aCHs7xwPwp1k6t15HY
oEVOictgob8mujBsT3FWFqNJxUCOLELJxRAwQrTZVqm9Zu4Qsgfit6WhAoGBAKWx
UbOUNU0JlSDBvaacpNsgUFmlnG1UhXHXrVPFAVE5QJeml5qRDCtb8sgQ6szTkCdb
nRHVqL2Olrz2O2OxF7KzPZ2pxzbfCkYXiUMmbgVXmtK4F0LALHyqeWIHwrml8oMo
WeY9MOvMSluO83LRORx5S3dht4AIZ/iTouLM5JxDAoGAcAnam49TeCFZuOu5/QCb
GYyAntOQL/nunSbuHoNvC+bBrcUX2BfDkalkzlm/YRJgmqSQ7Ih3fbp4i5NCVtpM
1dafoyed5UqY0F7Vou7JJE57tlKieKPhQOMTSl2Q5WMvby+owRb0Sx325xQvoslH
QM9+y6wy6YMdNweC+JkcZVo=
-----END PRIVATE KEY-----`


const ecPem256 = `-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgIyWeXcmAFz67wyXR
Ig6WJkxMK1LN01VsAFhToScH7fmgCgYIKoZIzj0DAQehRANCAARKQwgF3t7Vghb9
fVb6sqDXcsUCpQUBaCwCCIQeXD0wREFpcL3ZFTqrpvMAKDOHRINptdiZLyKPx+aC
AQPbE65D
-----END PRIVATE KEY-----
`

const ecPem384 = `-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDBMqpu1fyJWXuptimlt
x7INoLVOVI16BqbNyZcbkF0Tc4jkf6yLg8SuyeHLEAdmHdChZANiAAQ5ajF6xAhM
1hOM1CczqqQJ0MExaVcUam+ZaQbwvgvHw39S0I2fQAKuGpN0gCXshaR+wFB1TBtB
BLO4Bl28flhtdLI2XMtk0cPL41bExJkJmYSnFty7+zwWeJwf1ohiD64=
-----END PRIVATE KEY-----`

const ecPem521 = `-----BEGIN PRIVATE KEY-----
ABOrkYaelTH9A7QmhhsfIh8xHH1qH6wiraSbxp+zelO5K+xvs5A2yYXIG3NQkVye
tEkaA7xhMISRTsKnr+XR/sm1
-----END PRIVATE KEY-----`

const RsaSsaPem = `-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDhweJNGqo17TAP
DzWfZU+jswJ2v3GYD3VrgJngvQCuBZ/4lIq1Mn57zfzCdNFsinbqX68egiOY23ro
wcnYEWhgMbNWOTkfR6zptrV1ICCmVjRdplqQUPjXSIrfXuQEh6CO7t//fWNb1HyC
gRkcSSsMQE8+qj4xiADvLwr0fzaIGj+ggB1jyeTs84vCJyfgovW46Z+LlLJyifqi
eHoZYKmACsMRzIFoYprZl8jy3WapkJUccoCQ69yQRWJWVop68fcfv+EBQXCKBJ6e
3r44Ognf8tlmglJM/bgIemJCdoBiZ2vkVdNvAK2JfE+zSO3VgeCdQ+VdeOHGgfrx
joayrcErAgMBAAECggEAGpqJe4KX6lDwJ+Yn8Ie00dqngKzgywWPVcLK32QGb3t0
NYvzqJSxuQ82KQgxIbRTfR0XeuXlIf9DRaiIi7DJdwSEWLXXmGsO4l/IlGvbzR49
f4e6BmW0XVJMIzSAdFQzRIS72tTA37JzlcF23xF0RDZT4FOZjqazTXxisxtGptUQ
WxEwzXdkktuzr6H1dtQhH8Q5oBCBAhbIvLfH8m3dLX6x3uhoWZXr3lcHv8zaSnlE
0V/H4K8NY9cZNsFO9VSttaqP3JBMs4jApPAQLBK8T3e3C66rsMBpr2kxoRDsQt59
bKdxtnOlUnJkbxAaYGS7XNqH5vJPOTXpBClsV7M5wQKBgQD2ZBM2SgAFV2Yv+ICo
RpqLDhT+RqVzlZdk24hZvlmRTTueXrCdJglEFI5S8D2XvpWkUQt7uJIIr/cWQ1GP
QU2grdyxEBize8UbfXX4p4m2NQ8772YlQQgmKa6fxhzi0SposlLxH7vq+zwMYF/r
uwTa2Bkpd0xWmXYIx9GVPYpiIQKBgQDqj86X7BJER1j3kiw/EfEVDNY9wAp9l5OF
6nSHkhel9Z9mA4yeWc7/lRvSZgwqS57YtT1pAI+5MiGlNqLOp0YH8Ik08XO+OKmD
RfsdiObxC9htY0wP5Va2G0tpC2W8mbt+mYC73JlC1ZgsvDPoVMqpohmjSaSy1il5
GugNOzXRywKBgQDAtUD5gyNFCjiYaGpoMuCIxfjRb/vTzTpd3f5lAqYXKSrqEPFd
1/QDVXiDkfb6ikuL+v9aQt+k/8vnk7tkqhTHCXTE3+wR5Uoi2Bu+4XqqEhHaNMHV
fWmcP5meyVqqZCIhROfuQ328qccrfu1G+D0x1TbI4c/JI7nX4EEh0sI7QQKBgQDf
kvEFR8PlhugbGh3IhA551QGEXD7jlQ3NUDuAWVTnICat8uYerVWrsXGSayhfTDL9
NktxgVJ84HbHZjtqpHAQ80mkyBxdjN6uPI7tiOcvjO3e3g3K/PtYms2XM4DmctYP
Brt41PzUgokI4t7LLb76T4MGbBRrTcy8HVRgADb9XwKBgQCQWAF5l8Pmca4KNRoE
xuAi8yS4PXfgb9VcOPblDkKW0WYk79Z/G/st+JUCQ2Tg0LaDhI6YEWZa18HqQQH8
D49FzX7iUbjACERMNjOPXtursy/1/03ITnpgBHgOJgiXWbhrypv3DC5nEb7TK+98
Zr8NOd/6N3+nTwb4UXjaezf+BA==
-----END PRIVATE KEY-----`

const RsaPssPem = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDqNnCJ9yRjAaYH
AeZy/Y3RkqL2SVpOz1JKY+S+MnlObm8ll+Pm/i0N+RP7shGbg8B0MMyJ/HyKjV0W
lEw9Ab7MfY/OYZUNJBzz3kVhZEoCZ9Es0v4P+RAsPy8XVrMa95GXGH6nUXzknxaI
yVDg2FPZ0gpOfqFhOjI8F4g1czENpUqvR9RpdP7Owll8AtgZKgRrFTC8sU6cDRru
fobJnB3gToLUCufrmtu8l9IbedIpAlez5xISLtTXIRNvHrQy4tQYQbGlw0moFATE
6pKJ9KtUwVf93oG6Li92V9i8B9NksQ8cppBhfYkxFtVsmjtub9TTk1NeRdJTHoQq
Q0xKsEv7AgMBAAECggEAFB7FIDUI/TBhEO0K3QoHKt/L/BhlF6wbx6Q5PFWdsi0u
gy4/N9LSEAc7vj2X4aI54EFo8Nmt4UEvpAbtXbhOqcaHmhUr9ssJabHIiAtTiE1e
3NjrVnfw+bwb0YdzL3fhG/fQuZL4hbNc/jc9KXOsEGRI2mFqf62+Lwdefij9J8zH
OBEZ6NKvVkB9wN1R/IzhyfB8Ahwfqp+U6qY+FoG+p6luh0l6Qq3uFUfdR23JyK76
vpKSPjI0IBYlTJFix7AckdkAn1WeUspABoa3BvgxX3qNZAhMeCBR4IE56fDTjgPx
2Q2GC3+ZMZpqcOPTlqtfqEJ453p9vlc2OV6KGJokYQKBgQDq0yRrr8CErFMzUMur
edqs57AYnPDM0usvdX7bbpUVZ+UHJRpUDuCSWEGNH3zcwFIK3P+XNEHszXAW29RQ
Meazk6dAwKjpzmXrisWVza5MlfrKhf2kd+89CIgWBkPheI4LNCJoeYx4V8ezsAEj
OSf1YGZKeCwmZs5YA4ef8wXsQwKBgQD/VSqvezOD0phvrcIvWz8MRHN3IXlPXsPo
R3lQvm8br5wJs3yOlJo9mv7CJt0qOXST4pNpvCp1h4q6bbNd3KihkM8THnng4KgP
MDK9XRg/S1/XGq11qD8JrCWuYIUJWNWhX5ZLU6HqU3YNfQSQxhtL9avBDrAIdq65
z8InhCAB6QKBgBbYg+qWJrzBpzaO3cHJESVRRSif3C2RN6BeZgEjOQ3kFbwkN/OF
nwOd4oLAVX2EmHbGGXe0ddV8BzOyH23N7Qv7iYIbPFPC6NeJoL96S0LYNJYPgyXF
JVliwxqhcWk2OVuNrutLKAdtQtiQfwvWO7T7s/f6yRDTX6/gaAl/s0vRAoGBAMVD
Px8jx8DoSuy9CXEcxbDskWhQbDBtvl0OGyPOfHifS6YTDP/6vs8pl/jXnbapfO9j
9Q+TWBpFBWDSr+isOXvZLKJQwUiDSFOzoP+7lKgRy5GcArcLrOgEH3iBCUcXYrSx
7KN1kXo/0MzK8WQIKb6dpnwYpNdlGchkQlPVOAVBAoGBAK8f5UX9L1DjPgl46qtd
kifzbAT7MDZxiU/og33pVy4ZEKoXvOEl6u7a1ZPIQ5U4W7ZZXRE8un3eNW8n1Hto
ZWPAgQUUe8NfRLIu0u7lL1cDmwKqFb/Qvc1ImBWQGxZOt8mxs/g8+N8sQhUftVnQ
j7LSecVYPBKQpDvcAqREQjyd
-----END PRIVATE KEY-----`

const d = await pem2key(ecPem256); 
const a = await pem2key(RSAPrivateKeyPem, 512);
const b = await pem2key(RsaSsaPem,384);
const c = await pem2key(RsaPssPem);
