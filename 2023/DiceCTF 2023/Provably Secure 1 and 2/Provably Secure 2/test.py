ct1 = '1c98241fa34db4ed379f20041a3690a08f01b71c5a42d3980f4f0381be83d8d2857a8659a6df00545e4136f944ee24295e763e0e1e84075243b68c85973c05d592c578801d4657bfb163553ff66bb3ebd1d4466eeecf16ecdaa47047e3f7132356bea5b28e322858af39320966f546d8e8260762d4ebc321db01e96498a1e6363c38e6cf6fd2c5c5d727da50d0f323f7cac4343048f9d2917ec3180f35e5da4ef4b849c455d70031738789c7e34eb4c113391b97f958d573a35a898795bf0cc2dd82b0acfbf69ca1d69c880ae8317071786ff58f4665e0a81d990bc165b43f9f12534e57cb9efc837977ff7c10da24d74a67add927bfa7a351b9e7f41ce1d04c88440694ff5aa7795e5626fc08f7634ab1818d22cef66e493ef3df76181f7378a8401538eaa71f4eee7e1b2c7430efdacf302789a2dfdf3047344eaefe60bbeb36a055663c65f504059e8b768f1e7a93cca05f9eca17fd80e1463e0a1b54fa6100f17a66c2f33d7d565a84f9959fb0ede8fad11ca229bef23c51df9e6b9c7ceaeff3c58fac639e60dd47f5afc10bb8661d4fc44505743024abb6de44c7cc968c6b95cfd4b24eb5c7cda3adc11a28fe66bbaab1db4bde64cc3e00b2d255ef7b257af2fb508dcdb688de890f8a17c43eba15c0bca55990855be9bfe6cbab7f18d14c04276f6880ecdaa9501acfa6fd5829d3b82d1ffa8f68627321dba2c8e8a4d4'

ct1 = bytes.fromhex(ct1)

ct2 = '500661cea9343a5c4962a2b7dbd8f796fbad061ed19712538206b00650b8a30b69922a7566f0f3c37fec1c9128f0f85622c8e3c92eec19b146165b3b1e6bdf75d43faede62ff1bf45094df716328edcb97dec177aff5f087f123006e3f83a8c1202808d2e79eb5e854c1e34a8023f703a15ef48a0453164a128365d65bf166b8569f1ab9c9af134ac6a40b89b03022d7a953692dd673211ec37322965d3ddbff2ddb3ed85da5d2641f55b3ad8ea72e7cb9161e719e7e672e72a05dc6c4da4deab2283cb1d5340ff3a1f3b00472f0f4175208551570681864d895fa472566a948964701c17d5e3e7fb356321f6954a2245a139c85432844b6ded33cd2dab651edb5d95a3f7b7c2be4157f30a031b1369e0ef17150e4d74f17ef039a3aab61623e439535ffe96c1bb473b516ecad2910b652ed3dbabd0fa11fbbba338b37148d7d611b59ae1c7f2ceb15d1b8504d1dcfd013853f52409a0132fe2ca97c7f375169fa681c6cdc92e6faf3613ab6b70fa532705a67131419cb58c9207d2b7d50f185115ea6c55df179ea6e01193263785e92dc71ec278caf1c79fa651b36416ff3955b20ee369ab8fcaa852576dfd1fc5da1acca69fdb9b45aaed7c6d29b1f9084b9bfa605cd75d8e378bb3f648b838fc4583f924ded84b1e4514b792568dcef7de0cce7e78c26d4ee9d01dc274d7db85485977171afc952559c0daf52b0af554874'

ct2 = bytes.fromhex(ct2)

print((ct1[:256] + ct2[256:]).hex())
print()
print((ct2[:256] + ct1[256:]).hex())