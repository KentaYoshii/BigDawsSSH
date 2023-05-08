# gen key
openssl dsaparam 1024 -out params.pem
openssl gendsa params.pem -out dsa.key
openssl dsa -in dsa.key -pubout -out dsa.key.pub

# sign
openssl dgst -dss1 -sign dsa.key -out sig.data myfile.data

# verify
openssl dgst -dss1 -verify dsa.key.pub -signature sig.data myfile.data

# sign with my program
go build dsa.go

./dsa -action sign -key dsa.key -file myfile.data > sig.data
# ./dsa -action sign -key dsa.key -file myfile.data | penssl asn1parse -inform DER

# verify with my program
./dsa -action verify -pubkey dsa.key.pub -file myfile.data -signature sig.data