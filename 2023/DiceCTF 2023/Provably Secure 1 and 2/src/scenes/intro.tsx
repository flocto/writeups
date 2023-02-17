import { makeScene2D } from '@motion-canvas/2d/lib/scenes';
import { Circle, Image, Text } from '@motion-canvas/2d/lib/components';
import { createRef } from '@motion-canvas/core/lib/utils';
import { all, chain, delay, waitFor } from '@motion-canvas/core/lib/flow';
import { timing } from '../util';


export default makeScene2D(function* (view) {
  const pfp = createRef<Image>();
  view.add(
    <Image
      ref={pfp}
      src="pfp.png"
      width={200}
      height={200}
      x={480}
      y={270}
      opacity={0}
    />
  )

  // view.add(
  //   <Circle x={-650} y={260} width={180} height={180} fill="blue" >
  //     <Text fill={"white"} fontFamily={"monospace"} fontSize={48} y={10} text="Bob" />
  //   </Circle>
  // )

  // view.add(
  //   <Circle x={-350} y={270} width={180} height={180} fill="red" >
  //     <Text fill={"white"} fontFamily={"monospace"} fontSize={48} text="Alice" />
  //   </Circle>
  // )


  const introText =
    ['Hello! Welcome to my "video" writeup for Provably Secure 1 and 2 from DiceCTF 2023.',
      'This is intended to be a beginner-friendly writeup,\n so I will try to explain everything in detail.',
      'If you have any questions or feedback, feel free to leave a comment below. I hope you enjoy!']
    ;
  const txt = createRef<Text>();
  view.add(
    <Text
      ref={txt}
      fontSize={70}
      fontFamily="monospace"
      // y={-100}
      fill="white"
      maxWidth={1920}
      textWrap={true}
      alignItems="center"
      justifyContent="center"
      opacity={1} //?
    >
      Provably Secure 1 and 2 Writeup
    </Text>
  );

  yield* waitFor(1);

  yield* all(
    txt().opacity(0, 0.2),
    delay(0.3, pfp().opacity(1, 1.25)),
    delay(0.3, all(
      txt().position.y(0, 0.2),
      txt().fontSize(32, 0.2),
      txt().text(introText[0], 0.2),
      txt().maxWidth(960, 0.2),
      delay(0.2, txt().opacity(1, 0.6)),
    ))
  )


  yield* chain(
    waitFor(timing(introText[0])),
    txt().text(introText[1], 1),
    waitFor(timing(introText[1])),
    txt().text(introText[2], 1),
    waitFor(timing(introText[2])),
    all(
      pfp().position.y(-800, 1.25),
      pfp().scale(0.8, 0.8),
      pfp().opacity(0, 1.25),
      txt().position.y(100, 0.6),
      delay(0.3, all(
        txt().position.y(-800, 1),
        pfp().scale(60, 1)
      )),
    )
  );
});