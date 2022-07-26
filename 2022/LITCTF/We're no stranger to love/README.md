# We're no stranger to love
## Description
> OMG, the LIT Music Bot is playing my favorite song on the voice channel! Why does it sound a bit off tho?
## Attachments/Note
> This challenge used a bot that played audio in the LITCTF discord during the time of the contest. The full audio can be
found [here](FinalChallenge.mp3), but I will not be using it for the purposes of this writeup.
---

## RIP Rythm
Upon first hearing the audio, it sounds like a normal rickroll. However, sometimes the recording will glitch out and play
the same few milliseconds over and over for a bit, and also sometimes the among us game start sound effect will play in between
some of the glitches. (This entire sentence was not satire, seriously)

While listening, I noticed some of the glitches seemed to be longer than others, with there seeming to be 2 set lengths. The among us
sfx would also play after 1 or more of the glitches. This led me to assume that the among us sfx was meant to seperate letters.

Also, near the end of the song, I heard a text-to-speech voice say "Right curly bracket", telling me the flag was definitely hidden
as letters in the audio. After waiting for the song to loop, I counted 5 among us sfx's before the text-to-speech said "Left curly bracket".
This matches up with the flag prefix as well, as there are 6 letters before the curly bracket (LITCTF{...}). I assumed the last letter would be ended by the
curly bracket instead of a among us sfx as there was no reason for it to cut between a single letter. 

As for the glitches, I assumed they were either morse or binary because there seemed to only be 2 possible types, one long and one short. I leaned toward
morse because the long/short pattern matched that as well.

However, I wasn't really planning on solving that challenge until later because listening to the bot over and over was actually
pretty mentally taxing.

# OTZ OTZ OTZ OTZ ETH007 OTZ OTZ OTZ OTZ
Like I said one line above, I planned on saving some time at the end to write down the morse by hand while listening to the bot.

However, while browsing the discord, I managed to notice a message by the great and godly Eth007.

![OTZ OTZ OTZ](images/OTZ%20ETH007.png)

So, as it turns out, another bot being used on the server, MEE6, had the capability to record audio in a voice channel. Though it was limited
to 2 minutes at a time, nothing was stopping me from recording multiple times, so that's exactly what I did.

## Spectrogram looks better
I had to split the recording into 3 parts, with one part overlapping and a few seconds being cut off in the middle. 
But in the end, I managed to get the entire song as local files, which I just put on Audacity.

In Audacity, it's still pretty hard to see the glitches normally, which I why I switched to spectrogram mode, as it makes them show up much easier.

![spectrogram viewing](images/spectro%20op.png)

The glitches show up as stripes because they repeat the same audio.
Also, the among us sfx stands out a lot too, making decoding easier. 

In this case, the above segment would translate to `.-.. .. - -.-.`, which translates to `LITC`, the first part of the flag format.
We just have to repeat this for the entire song, which actually doesn't take too long as everything stands out in spectrogram. 

Translating the entire message with the curly brackets, we get 
```
.-.. .. - -.-. - ..-. { .-. .. -.-. -.- .. ..-. .. . -.. }
```
which then becomes
```
LITCTF{RICKIFIED}
```

## Notes
Actually in the 3 parts I only got LITCTF{RICKIF_ED} as the I got cut out, but it was fairly easy to guess from the other letters.

Also orz Eth007 for giving me a much easier way to solve the problem and I'm pretty surprised not that many people caught on to it. But I probably
wouldn't have solved as easily as I did without his message <3.

![so orz](images/so%20orz.png)