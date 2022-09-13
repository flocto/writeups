# DockREleakage

> A breach occurred and some files have been leaked. One of the leaked files named dockREleakage.tar.gz contains an image of one of the company's components. An anonymous hacker has reached out to me and beware me that there is some serious mistake in my build image process. The hacker implies that sensitive information should be handled carefully. However, I couldn't find the mistake by myself. Please help me!

## Attachments

> [dockREleakage.tar.gz](dockREleakage.tar.gz)

---

### **_DISCLAIMER_**

I used a JSON formatter for the JSON files used in the challenge. The JSON files come unformatted originally out of the zip. You can format using a site like Prettier or some IDE extensions (I used VSCode + Prettier)

# Long names

We're given a zipped tar, so let's extract that and look at its contents. If you're on Windows 10+ and don't have an archive program like WinRAR or 7-Zip or whatever, you can use a command line with administrator privileges and run:

```
directory\with\targz> tar -xvf archive.tar.gz -C <output directory>
```

The extracted files should be in the output directory (if you don't specify one it will just extract to the current directory).

After extracting, we get a folder that looks like this (truncated long file names):

```
> dockREleakage
    > 4e39xxx
        > json
        > layer.tar
        > VERSION
    > 4ec4xxx
        > json
        > layer.tar
        > VERSION
    > 928axxx
        > json
        > layer.tar
        > VERSION
    > 3870xxx
        > json
        > layer.tar
        > VERSION
    > a675xxx
        > json
        > layer.tar
        > VERSION
    > acbbxxx.json
    > manifest.json
    > repositories
```

Ignoring the random hexadecimal folders and json, let's take a look at `manifest.json` and `repositories`.

## Docker

Before I go over the contents of each file, I want to go over what we are actually looking at.

If you haven't noticed yet, either by the title or by the files, we're working with a Docker image.
Docker is a program that allows for easy virtualization using different containers to simulate entire operating systems.

To create a container, a Docker image is needed, which can be created using a script known as a Dockerfile. This Dockerfile contains instructions that outline how to create the image.

What we are given for this challenge is the layers of a Docker image and the associated manifest for that image. A Docker manifest is basically a description of the layers of the image.

### manifest.json

Looking at [manifest.json](dockREleakage/manifest.json):

```json
[
  {
    "Config": "acbb216b17482071caca135101282177f6ffed7b8ee0bfc5323aae103c216d74.json",
    "RepoTags": ["dockre-chal:latest"],
    "Layers": [
      "3870e289882c4fdbcc30578a229ae67baa48cf5a24ef5d33572eea40e6fc7328/layer.tar",
      "4e390957050a16edef4222dcca6fe7ff82ee76bdda9013b147bbbee0c260be24/layer.tar",
      "a67551c4bf4a0beef636c26e22aa4205fececa2a3fe51c906affd158d13fa038/layer.tar",
      "4ec42253273e93963f11241e29497f0fcef730a2864d8ea025dcdb4fc316659e/layer.tar",
      "928ab519cd995aeae5eced3dbe4b7e86c8bc7f7662ef0f73e59c2f30b2b3b8e4/layer.tar"
    ]
  }
]
```

We notice that the `Config` label holds the name of the other json file, while each of the layers is the names of the 5 folders followed by `layer.tar`.

Inside of `repositories`, we find a simple line with what I assumed to be the uppermost layer:

```json
{
  "dockre-chal": {
    "latest": "928ab519cd995aeae5eced3dbe4b7e86c8bc7f7662ef0f73e59c2f30b2b3b8e4"
  }
}
```

Let's look into the config json first, before diving into each layer and seeing what we can find.

## Configuration

Scrolling past a lot of the standard configuration, we find a section that is of interest

```json
"history": [
    {
      "created": "2022-08-09T17:19:53.274069586Z",
      "created_by": "/bin/sh -c #(nop) ADD file:2a949686d9886ac7c10582a6c29116fd29d3077d02755e87e111870d63607725 in / "
    },
    {
      "created": "2022-08-09T17:19:53.47374331Z",
      "created_by": "/bin/sh -c #(nop)  CMD [\"/bin/sh\"]",
      "empty_layer": true
    },
    {
      "created": "2022-09-03T07:46:11.653961901Z",
      "created_by": "/bin/sh -c #(nop) WORKDIR /chal"
    },
    {
      "created": "2022-09-03T07:46:11.863666686Z",
      "created_by": "/bin/sh -c #(nop) COPY file:d65d0cfa1f5c483eff02b6016940ff4d85eb3b216f05d23a2b891cea6801be2a in p-flag.txt "
    },
    {
      "created": "2022-09-03T07:46:12.680399343Z",
      "created_by": "/bin/sh -c echo \"ZmxhZ3tuM3Yzcl9sMzR2M181M241MTcxdjNfMW5mMHJtNDcxMG5fdW5wcjA=\" \u003e /dev/null",
      "empty_layer": true
    },
    {
      "created": "2022-09-03T07:46:13.319972067Z",
      "created_by": "/bin/sh -c cat p-flag.txt \u003e tmp.txt; rm -rf flag.txt p-flag.txt; mv tmp.txt flag.txt; echo \"\" \u003e\u003e flag.txt"
    },
    {
      "created": "2022-09-03T07:46:14.02363242Z",
      "created_by": "/bin/sh -c echo \"Find the rest of the flag by yourself!\" \u003e\u003e flag.txt"
    },
    {
      "created": "2022-09-03T07:46:14.235116602Z",
      "created_by": "/bin/sh -c #(nop)  CMD [\"/bin/sh\"]",
      "empty_layer": true
    }
  ],
```

Just a bit of clarification before I move on, `\u003e` is meant to be the `>` character, which if you are at all familiar with Bash, is used to pipe output into files.

One particular part that stood out especially to me was

```json
    {
      "created": "2022-09-03T07:46:12.680399343Z",
      "created_by": "/bin/sh -c echo \"ZmxhZ3tuM3Yzcl9sMzR2M181M241MTcxdjNfMW5mMHJtNDcxMG5fdW5wcjA=\" \u003e /dev/null",
      "empty_layer": true
    },
```

A long string is echoed into `/dev/null`, which is a file that just goes nowhere, so basically the string is deleted. This stands out as there would be no reason to run this command if you are just echoing something in `/dev/null`.

### Base64

If you know what base64 is, you should immediately recognize the string as base64. If not, then just know that base64 is a way for data to be encoded. **It does not provide any actual security and can easily be converted back into its original data.**

Converting the echoed string, we get an output that looks like the first part of the flag

```
>>> echo "ZmxhZ3tuM3Yzcl9sMzR2M181M241MTcxdjNfMW5mMHJtNDcxMG5fdW5wcjA=" | base64 -d
flag{n3v3r_l34v3_53n5171v3_1nf0rm4710n_unpr0
```

To get the other half, we probably have to look into the actual layers of the image.

## layer.tar

Looking at the rest of the commands, we see a file, `flag.txt`, that might be interesting

```json
    {
      "created": "2022-09-03T07:46:13.319972067Z",
      "created_by": "/bin/sh -c cat p-flag.txt \u003e tmp.txt; rm -rf flag.txt p-flag.txt; mv tmp.txt flag.txt; echo \"\" \u003e\u003e flag.txt"
    },
    {
      "created": "2022-09-03T07:46:14.02363242Z",
      "created_by": "/bin/sh -c echo \"Find the rest of the flag by yourself!\" \u003e\u003e flag.txt"
    },
```

From what we know earlier, the uppermost layer of the Docker image should be `928ab519cd995aeae5eced3dbe4b7e86c8bc7f7662ef0f73e59c2f30b2b3b8e4`. Going into that folder, we can try extracting the `layer.tar`, which should contain the associated files for that layer.

The extraction process is similar to the one for the main `dockREleakage.tar.gz`.

### flag.txt

After extracting the [layer](chal/), we find a [file called flag.txt](chal/flag.txt) containing the second half of the flag.

```
73c73d_w17h1n_7h3_d0ck3rf1l3}
Find the rest of the flag by yourself!
```

Combining the two together, we get our final flag:

```
flag{n3v3r_l34v3_53n5171v3_1nf0rm4710n_unpr073c73d_w17h1n_7h3_d0ck3rf1l3}
```

## Conclusion

This challenge is a good introduction to how Docker actually creates its images and how they are stored. Even if you know nothing about Docker, basic knowledge of base64 and knowing how to untar archives can solve you the challenge, which is also nice.
