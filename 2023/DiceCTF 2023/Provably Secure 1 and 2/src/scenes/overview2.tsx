import { makeScene2D } from '@motion-canvas/2d/lib/scenes';
import { Layout, Circle, Latex, Text } from '@motion-canvas/2d/lib/components';
import { createRef, } from '@motion-canvas/core/lib/utils';
import { delay, chain, all, waitFor } from '@motion-canvas/core/lib/flow';
import {
    CodeBlock,
    edit,
    insert,
    lines,
    remove,
} from '@motion-canvas/2d/lib/components/CodeBlock';
import { timing } from '../util';


export default makeScene2D(function* (view) {
    const text = createRef<Text>();
    view.add(
        <Text
            ref={text}
            fill="white"
            opacity={0}
            fontFamily="monospace"
            fontSize={32}
            maxWidth={1320}
            textWrap={true}
            text="Provably Secure 2 fixes the fatal bug from earlier, so we actually need to exploit the encryption."
        />
    );

    const bob = createRef<Circle>();
    const alice = createRef<Circle>();
    const m0 = createRef<Circle>();
    const m1 = createRef<Circle>();
    const m0_ltx = createRef<Latex>();
    const m1_ltx = createRef<Latex>();
    const visual = createRef<Layout>();

    view.add(
        <Layout opacity={0} ref={visual}>
            <Circle ref={bob} x={-550} y={190} width={180} height={180} fill="blue" >
                <Text fill={"white"} fontFamily={"monospace"} fontSize={48} y={10} text="Bob" />
            </Circle>
            <Circle ref={alice} x={550} y={200} width={180} height={180} fill="red" >
                <Text fill={"white"} fontFamily={"monospace"} fontSize={48} text="Alice" />
            </Circle>
            <Circle ref={m0} x={-400} y={150} width={75} height={75} fill="green" >
                <Latex ref={m0_ltx} width={60} tex="\color{white} m_0" />
            </Circle>
            <Circle ref={m1} x={-400} y={250} width={75} height={75} fill="green" >
                <Latex ref={m1_ltx} width={60} tex="\color{white} m_1" />
            </Circle>
        </Layout>
    )

    const textsegments = [
        `Let's take another look at the encryption scheme.`,
        `In particular, let's look at what happens when we encrypt the same message pair two times.`,
        `Recall that encryption gives us E(r) and E(r xor mb), where r is some random bytes and mb is one of the two messages.`,
        `Because r is generated randomly for each encryption, I'll mark r1 for the first encryption and r2 for the second, same for mb.`,
        `Let's save the first ciphertext, and now encrypt the same message pair again.`,
        `Notice that when we decrypt, we can swap parts of the two ciphertexts as long as they decrypt under the same key.(E1 to E1, E2 to E2)`,
        `We need to swap the ciphertext parts because the flaw that allowed us to decrypt any ciphertext is fixed, and we can only
        decrypt ciphertexts that weren't directly returned by the encryption oracle.`,
        `The only problem is that the final output will look like garbage, as it contains both r1, r2 and mb, meaning we can't get back
        the original message as we don't know r1 and r2.`,
        `However, we can use the fact that we control the messages to our advantage.`,
        `If we try to decrypt both swapped pairs, r1 with r2mb2 and r2 with r1mb1, we should get messages that contain
        both r1 ^ r2, but with different mbs.`,
        `But notice that if mb1 is the same as mb2, then we should get the same exact thing!`,
        `Since we control all messages, all we have to do is change exactly one message in the pair and encrypt it again.`,
        `This way, when we swap the ciphertext pairs, we should get final decryption outputs that look like r1r2mb1 and r1r2mb2 respectively.`,
        `If they're equal, then mb1 is equal to mb2, meaning m_bit selected whichever message stayed the same.`,
        `But if they're different, then mb1 is not equal to mb2, meaning m_bit selected whichever message changed.`,
        `This attack allows us to fully recover m_bit in only 2 encryptions and 2 decryptions!`,
    ]
    yield* text().opacity(1, 1);
    yield* waitFor(timing('Provably Secure 2 fixes the fatal bug from earlier, so we actually need to exploit the encryption.'));
    yield* text().text(textsegments[0], 0.75);
    yield* waitFor(timing(textsegments[0]));
    yield* all(
        text().position.y(-300, 1),
        text().text(textsegments[1], 0.75),
        visual().opacity(1, 1),
        waitFor(timing(textsegments[1]) + 0.75),
    )

    yield* all(
        m0().position.x(375, 0.75),
        m1().position.x(375, 0.75),
        delay(0.5, all(
            m0().opacity(0, 0.5),
            m1().opacity(0, 0.5),
        ))
    )


    yield* all(
        text().text(textsegments[2], 0.75),
        m0().fill("purple", 0.5),
        m1().fill("purple", 0.5),
        m0_ltx().tex("\\color{white} E_1(r_1)", 0),
        m1_ltx().tex("\\color{white} E_2(r_1 \\oplus m_{b1})", 0),
        m0_ltx().size.x(100, 0.5),
        m1_ltx().size.x(200, 0.5),
        delay(1, all(
            m0().opacity(1, 0.5),
            m1().opacity(1, 0.5),
            delay(1, all(
                m0().position.x(-375, 0.75),
                m1().position.x(-375, 0.75),
                waitFor(2.5),
            ))
        ))
    );

    yield* all(
        text().text(textsegments[3], 0.75),
        waitFor(timing(textsegments[3]) + 0.5),
    )

    yield* all(
        text().text(textsegments[4], 0.75),
        waitFor(1.5),
    )

    const r1_ltx = m0_ltx().snapshotClone();
    const r1mb_ltx = m1_ltx().snapshotClone();

    const r1 = m0().snapshotClone({ children: [r1_ltx] });
    const r1mb = m1().snapshotClone({ children: [r1mb_ltx] });
    view.add(
        <>
            {r1}
            {r1mb}
        </>
    )

    yield* all(
        r1.position.y(350, 0.75),
        r1mb.position.y(450, 0.75),
        m0().fill("green", 0.5),
        m1().fill("green", 0.5),
        m0_ltx().size.x(60, 0.5),
        m1_ltx().size.x(60, 0.5),
        delay(0.5, all(
            m0_ltx().tex("\\color{white} m_0", 0),
            m1_ltx().tex("\\color{white} m_1", 0)
        )),
        waitFor(1.25),
    )

    yield* all(
        m0().position.x(375, 0.75),
        m1().position.x(375, 0.75),
        delay(0.5, all(
            m0().opacity(0, 0.5),
            m1().opacity(0, 0.5),
        ))
    )

    yield* all(
        m0().fill("indigo", 0.5),
        m1().fill("indigo", 0.5),
        m0_ltx().tex("\\color{white} E_1(r_2)", 0),
        m1_ltx().tex("\\color{white} E_2(r_2 \\oplus m_{b2})", 0),
        m0_ltx().size.x(100, 0.5),
        m1_ltx().size.x(200, 0.5),
        delay(1, all(
            m0().opacity(1, 0.5),
            m1().opacity(1, 0.5),
            delay(1, all(
                m0().position.x(-375, 0.75),
                m1().position.x(-375, 0.75),
                waitFor(2),
            ))
        ))
    );

    yield* all(
        text().text(textsegments[5], 0.75),
        waitFor(timing(textsegments[5])),
        delay(1, all(
            r1mb.position.y(250, 1.5),
            r1mb.position.x(-300, 0.75).to(-375, 0.75),
            m1().position.y(450, 1.5),
            m1().position.x(-450, 0.75).to(-375, 0.75),
        ))
    )

    yield* all(
        text().text(textsegments[6], 0.75),
        waitFor(timing(textsegments[6]) + 0.5),
    )

    yield* all( // LMFAO italian ancestry
        text().text(textsegments[7], 0.75),
        waitFor(timing(textsegments[7])),
        delay(1, all(
            m0().position.x(375, 0.75),
            r1mb.position.x(375, 0.75),
            delay(0.5, all( // send over to alice, fade
                m0().opacity(0, 0.5),
                r1mb.opacity(0, 0.5),
                delay(0.75, all( // alice decryption
                    m0().fill("sienna", 0),
                    r1mb.fill("sienna", 0),
                    m0_ltx().tex("\\color{white} r_2", 0),
                    m0_ltx().size.x(60, 0),
                    r1mb_ltx.tex("\\color{white} r_1 \\oplus m_{b1}", 0),

                    m0().opacity(1, 0.5),
                    r1mb.opacity(1, 0.5),
                    delay(1, all( // alice xor
                        m0().position.y(120, 0.4).to(200, 0.4),
                        r1mb.position.y(290, 0.4).to(200, 0.4),

                        delay(0.75, all( // alice xor pt 2
                            m0().fill("green", 0.5),
                            m0_ltx().tex("\\color{white} r_1 \\oplus r_2 \\oplus m_{b1}", 0),
                            m0_ltx().size.x(225, 0.5),
                            r1mb.opacity(0, 1),
                            delay(1, all( // send to bob
                                m0().position.x(-375, 1),
                                r1mb.position.x(-375, 1), // haha lol
                            ))
                        ))
                    ))
                ))
            ))
        ))
    )

    yield* all(
        text().text(textsegments[8], 0.75),
        waitFor(timing(textsegments[8]) + 0.5),
    )

    yield* all(
        text().text(textsegments[9], 0.75),
        m0().position.y(400, 0.75),
        r1.position.y(150, 0.75),
        m1().position.y(250, 0.75),
    )

    yield waitFor(1);

    yield* all(
        r1.position.x(375, 0.75),
        m1().position.x(375, 0.75),
        delay(0.5, all( // send over to alice, fade
            r1.opacity(0, 0.5),
            m1().opacity(0, 0.5),
            delay(0.75, all( // alice decryption
                r1.fill("sienna", 0),
                m1().fill("sienna", 0),
                r1_ltx.tex("\\color{white} r_2", 0),
                r1_ltx.size.x(60, 0),
                m1_ltx().tex("\\color{white} r_1 \\oplus m_{b2}", 0),

                r1.opacity(1, 0.5),
                m1().opacity(1, 0.5),
                delay(1, all( // alice xor
                    r1.position.y(120, 0.4).to(200, 0.4),
                    m1().position.y(290, 0.4).to(200, 0.4),

                    delay(0.75, all( // alice xor pt 2
                        r1.fill("#003200", 0.5),
                        r1_ltx.tex("\\color{white} r_1 \\oplus r_2 \\oplus m_{b2}", 0),
                        r1_ltx.size.x(225, 0.5),
                        m1().opacity(0, 1),
                        delay(1, all( // send to bob
                            r1.position.x(-375, 1),
                            m1().position.x(-375, 1), // haha lol
                        ))
                    ))
                ))
            ))
        ))
    )


    yield* all(
        text().text(textsegments[10], 0.75),
        waitFor(timing(textsegments[10]) + 0.5),
        delay(0.5, all(
            r1.position([-150, 200], 0.75),
            r1.size([125, 125], 0.75),
            r1_ltx.size.x(275, 0.75),

            m0().position([150, 200], 0.75),
            m0().size([125, 125], 0.75),
            m0_ltx().size.x(275, 0.75),

            delay(1.25, all(
                r1_ltx.opacity(0, 0.5),
                m0_ltx().opacity(0, 0.5),
                delay(0.5, all(
                    r1_ltx.tex("\\color{white} r(m_{b2})", 0),
                    r1_ltx.size.x(150, 0),
                    m0_ltx().tex("\\color{white} r(m_{b1})", 0),
                    m0_ltx().size.x(150, 0),
                    r1_ltx.opacity(1, 0.5),
                    m0_ltx().opacity(1, 0.5),
                ))
            ))
        ))
    )

    yield* all(
        text().text(textsegments[11], 0.75),
        waitFor(timing(textsegments[11]) + 0.5),
    )

    yield* all(
        text().text(textsegments[12], 0.75),
        waitFor(timing(textsegments[12]) + 0.5),
        delay(1.5, chain(
            r1.position.y(150, 0.4).to(200, 0.4),
            waitFor(0.3),
            m0().position.y(150, 0.4).to(200, 0.4),
        ))
    )

    const equals = createRef<Latex>();
    view.add(
        <Latex
            ref={equals}
            y={200}
            width={100}
            opacity={0}
            tex={"\\color{white} ="}
        >
        </Latex>
    );

    yield* all(
        text().text(textsegments[13], 0.75),
        waitFor(timing(textsegments[13]) + 0.5),
        equals().opacity(1, 0.5),
    )

    yield* all(
        text().text(textsegments[14], 0.75),
        waitFor(timing(textsegments[14]) + 0.5),
        equals().opacity(0, 0.3),
        delay(0.5, all(
            equals().tex("\\color{white} \\neq", 0),
            equals().opacity(1, 0.5),
        ))
    )

    yield* all(
        text().text(textsegments[15], 0.75),
        waitFor(timing(textsegments[15]) + 0.5),
    )

    yield* all(
        visual().opacity(0, 0.5),
        r1.opacity(0, 0.5),
        equals().opacity(0, 0.5),
    )

    yield* all(
        text().opacity(0, 1)
    )
});