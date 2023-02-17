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
    const code = createRef<CodeBlock>();
    const text = createRef<Text>();
    const codesegments = [
        `key0 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key1 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pk0 = key0.public_key()
    pk1 = key1.public_key()
    print("pk0 =", pk0.public_numbers().n)
    print("pk1 =", pk1.public_numbers().n)
    `,
        `m_bit = randbits(1) # 0 or 1
    seen_ct = set()
    en_count = 0
    de_count = 0
    `,
        `while True:
    choice = int(input("Action: "))
    `,
        `if choice == 0:
        guess = int(input("m_bit guess: "))
        if (guess == m_bit):
            print("Correct!")
            break
        else:
            print("Wrong!")
            exit(0)`,
        `elif choice == 1:
        en_count += 1
        if (en_count > 8):
            print("You've run out of encryptions!")
            exit(0)
        m0 = bytes.fromhex(input("m0 (16 byte hexstring): ").strip())
        m1 = bytes.fromhex(input("m1 (16 byte hexstring): ").strip())
        if len(m0) != 16 or len(m1) != 16:
            print("Must be 16 bytes!")
            exit(0)
        msg = m0 if m_bit == 0 else m1
        ct = encrypt(pk0, pk1, msg)
        seen_ct.add(ct)
        print(ct)`,
        `elif choice == 2:
        de_count += 1
        if (de_count > 8):
            print("You've run out of decryptions!")
            exit(0)
        in_ct = bytes.fromhex(input("ct (512 byte hexstring): ").strip())
        if len(in_ct) != 512:
            print("Must be 512 bytes!")
            exit(0)
        if in_ct in seen_ct:
            print("Cannot query decryption on seen ciphertext!")
            exit(0)
        print(decrypt(key0, key1, in_ct).hex())`,
    ]

    const textsegments = [
        `Let's start with an overview of the first problem, Provably Secure 1.`,
        `First, we go through 128 loops,`,
        `On each loop, the server generate two RSA keys, then prints the public modulus of each key.`,
        `Then, the server also sets some constants, with m_bit being either 1 or 0 randomly.`,
        `Next, the server enters into a while loop, where it waits for the user to input an action as a number.`,
        `If the user inputs 0, the server will ask for a guess of m_bit.`,
        `If the user guesses correctly, the server will break out of the while loop and continue to the next iteration of the for loop.`,
        `If the user guesses incorrectly, the server will exit the program.`,
        `If the user inputs 1, the server will ask for two 16-byte messages in hex, m0 and m1.`,
        `It then encrypts one of the messages, m0 or m1, based on the value of m_bit. It adds the ciphertext to a set of seen ciphertexts, and prints the ciphertext.`,
        `As we don't know m_bit, we aren't supposed to know which message was encrypted.`,
        `Also, we only get 8 chances to encrypt a message before the server exits.`,
        `Finally, if the user inputs 2, the server will ask for a 512-byte ciphertext in hex.`,
        `If the decoded ciphertext is in the set of seen ciphertexts, the server will refuse to decrypt it, and exit the program.`,
        `The server then decrypts the ciphertext, and prints the result.`,
        `Same as before, we only get 8 chances to decrypt a message before the server exits.`,
    ]

    view.add(
        <>
            <CodeBlock
                ref={code}
                maxWidth={840}
                x={-400}
                fontSize={28}
                lineHeight={38}
                alignItems='start'
                language='python'
                code={() => `for experiment in range(1, 129):
    print("Experiment {}/128".format(experiment))`}
                opacity={0}
            />
            <Text
                ref={text}
                fontSize={32}
                fontFamily="monospace"
                fill="white"
                x={500}
                y={-250}
                maxWidth={840}
                textWrap={true}
                opacity={0}
            >
                {textsegments[0]}
            </Text>
        </>
    );

    yield* all(
        text().opacity(1, 1),
        code().opacity(1, 1),
    )

    yield* waitFor(timing(textsegments[0]));
    yield* text().text(textsegments[1], 0.5);
    yield* waitFor(timing(textsegments[1]));
    yield* text().text(textsegments[2], 0.5);

    yield* code().edit(2.5)`for experiment in range(1, 129):
    print("Experiment {}/128".format(experiment))${insert('\n    ' + codesegments[0])}`;
    yield* waitFor(1.5);
    yield* code().selection(lines(0, Infinity), 0.3);

    yield* all(
        delay(0.3, text().text(textsegments[3], 0.1)),
        text().position.y(350, 1),
    );
    yield* code().edit(2.5)`for experiment in range(1, 129):
    print("Experiment {}/128".format(experiment))
    ${codesegments[0]}${insert(codesegments[1])}`;
    yield* waitFor(0.5);
    yield* code().selection(lines(0, Infinity), 0.3);
    yield* waitFor(timing(textsegments[3]) - 1.75);

    // code gets wiped
    yield* all(
        code().edit(2)`${edit(`for experiment in range(1, 129):
    print("Experiment {}/128".format(experiment))
    ${codesegments[0]}${codesegments[1]}`, codesegments[2])}`,
        text().text(textsegments[4], 0.5),
        text().position.y(250, 0.5),
    );
    yield* waitFor(timing(textsegments[4]) - 0.5);

    yield* all(
        code().edit(1.5)`${codesegments[2]}${insert(codesegments[3])}`,
        delay(1.5, code().selection(lines(2, 3), 0.5)),
        text().text(textsegments[5], 0.5),
    );

    yield* waitFor(timing(textsegments[5]));

    yield* all(
        code().selection(lines(4, 6), 0.5),
        text().text(textsegments[6], 0.5)
    )
    yield* waitFor(timing(textsegments[6]));

    yield* all(
        code().selection(lines(7, 9), 0.5),
        text().text(textsegments[7], 0.5)
    )
    yield* waitFor(timing(textsegments[7]));

    yield* all(
        text().text(textsegments[8], 0.5),
        code().edit(1.5)`${codesegments[2]}${edit(codesegments[3], codesegments[4])}`,
        delay(1.5, code().selection(lines(7, 11), 0.5)),
        waitFor(timing(textsegments[8]) + 0.5),
    )

    yield* all(
        text().text(textsegments[9], 0.5),
        code().selection(lines(12, 15), 0.5),
        waitFor(timing(textsegments[9]) + 0.5),
    )

    yield* all(
        text().text(textsegments[10], 0.5),
        code().selection(lines(0, Infinity), 0.3),
        delay(0.5, code().edit(1)`${insert(`m_bit = randbits(1) # 0 or 1\n`)}${codesegments[2]}${codesegments[4]}`),
        waitFor(timing(textsegments[10]) + 0.5),
    )

    yield* all(
        text().text(textsegments[11], 0.5),
        code().selection(lines(4, 7), 0.5),
        waitFor(timing(textsegments[11])),
    )

    yield* all(
        code().edit(1.5)`${remove(`m_bit = randbits(1) # 0 or 1\n`)}${codesegments[2]}${edit(codesegments[4], codesegments[5])}`,
        text().text(textsegments[12], 0.5),
        text().position.y(-250, 0.5),
        delay(1.5, code().selection(lines(7, 10), 0.5)),
        waitFor(timing(textsegments[12]) + 0.5),
    )

    yield* all(
        text().text(textsegments[13], 0.5),
        code().selection(lines(11, 13), 0.5),
        waitFor(timing(textsegments[13]) + 0.5),
    )

    yield* all(
        text().text(textsegments[14], 0.5),
        code().selection(lines(14, 14), 0.5),
        waitFor(timing(textsegments[14]) + 0.5),
    )

    yield* all(
        text().text(textsegments[15], 0.5),
        code().selection(lines(3, 6), 0.5),
        waitFor(timing(textsegments[15]) + 0.5),
    )

    // PART 2
    // Oracle overview

    const descsegments = [
        `Let's briefly go over how the entire system works with stepping into too much detail and code.`,
        `We as the client, Bob, can send two messages, m0 and m1, to the server, Alice.`,
        `Alice will then send back a message with two seperate encrypted parts, E1(r) and E2(r ^ mb). 
        (They are concatenated together in the output but should be considered seperate)`,
        `This encryption is done using two keys, with E1 using K1 and E2 using K2.`,
        `As for the values, r is some randomly generated bytes and mb is chosen from m0 or m1 based on the value of m_bit.`,
        `Notice that mb is never directly encrypted, only r and r xor mb.`,
        `When Alice decrypts a message, she first decrypts the two parts seperately, getting r and r xor mb.`,
        `She then xor's the two parts together to cancel out r and recover mb.`,
        `This cryptosystem is meant to be set up to be IND-CPA secure.`,
        `This cryptosystem is meant to be set up to be IND-CPA secure, or have INDistinguishability under Chosen Plaintext Attack.`,
        `This means that we, as the client, shouldn't be able to tell which message Alice encrypted.`,
        `However, if we can guess m_bit 128 times in a row, we can prove that this cryptosystem is not IND-CPA secure, and get the flag.`,
    ]
    yield* all(
        code().edit(1.5)`${remove(codesegments[2])}${remove(codesegments[5])}`,
        delay(1,
            all(
                text().position.y(-50, 0.5),
                text().position.x(0, 0.5),
                delay(0.5, text().text(descsegments[0], 0.5)),
                waitFor(timing(descsegments[0]) + 1),
            ),
        ),
    )

    const bob = createRef<Circle>();
    const alice = createRef<Circle>();
    const m0 = createRef<Circle>();
    const m1 = createRef<Circle>();
    const m0_ltx = createRef<Latex>();
    const m1_ltx = createRef<Latex>();
    const visual = createRef<Layout>();

    yield* all(
        text().position.y(-150, 0.5),
        text().maxWidth(960, 0.5),
    )

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

    yield* all(
        visual().opacity(1, 0.5),
        waitFor(1),
    )

    yield* all(
        text().text(descsegments[1], 0.5),
        delay(0.9,
            chain(
                bob().position.y(150, 0.4).to(190, 0.4),
                waitFor(0.3),
                all(
                    m1().position.y(210, 0.4).to(250, 0.4),
                    m0().position.y(110, 0.4).to(150, 0.4),
                ),
                waitFor(timing(descsegments[1]) - 2.5),
            )
        )
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
        text().text(descsegments[2], 0.5),
        m0().fill("purple", 0.5),
        m1().fill("purple", 0.5),
        m0_ltx().tex("\\color{white} E_1(r)", 0),
        m1_ltx().tex("\\color{white} E_2(r \\oplus m_b)", 0),
        m0_ltx().size.x(100, 0.5),
        m1_ltx().size.x(200, 0.5),
        delay(1, all(
            m0().opacity(1, 0.5),
            m1().opacity(1, 0.5),
            delay(1, all(
                m0().position.x(-375, 0.75),
                m1().position.x(-375, 0.75),
                waitFor(timing(descsegments[2]) - 3.5),
            ))
        ))
    );

    yield* all(
        text().text(descsegments[3], 0.5),
        chain(
            waitFor(1.25),
            m0().position.y(110, 0.4).to(150, 0.4),
            waitFor(0.3),
            m1().position.y(210, 0.4).to(250, 0.4),
            waitFor(timing(descsegments[3]) - 2),
        ),
    );

    yield* chain(
        text().text(descsegments[4], 0.5),
        waitFor(timing(descsegments[4])),
        text().text(descsegments[5], 0.5),
        waitFor(timing(descsegments[5])),
    );

    yield* all(
        text().text(descsegments[6], 0.5),
        delay(0.5,
            all(
                m0().position.x(375, 0.75),
                m1().position.x(375, 0.75),
                delay(0.5,
                    all(
                        m0().opacity(0, 0.5),
                        m1().opacity(0, 0.5),
                        chain( // lmao this is so ugly
                            waitFor(0.5),
                            all(
                                m0_ltx().tex("\\color{white} r", 0),
                                m0_ltx().size.x(35, 0),
                                m0().fill("Sienna", 0),
                            ),
                            m0().opacity(1, 0.5),
                            waitFor(0.5),
                            all(
                                m1_ltx().tex("\\color{white} r \\oplus m_b", 0),
                                m1_ltx().size.x(120, 0),
                                m1().fill("Sienna", 0),
                            ),
                            m1().opacity(1, 0.5),
                            waitFor(0.5),
                        )
                    )
                )
            )
        ),
    );

    yield* all(
        text().text(descsegments[7], 0.5),
        chain(
            waitFor(0.8),
            all(
                m0().position.y(130, 0.25).to(200, 0.4),
                m1().position.y(270, 0.25).to(200, 0.4),
                delay(0.5,
                    all(
                        m1().opacity(0, 0.5),
                        m1().fill("green", 0.5),
                        m1_ltx().tex("\\color{white} m_b", 0),
                        m0().fill("green", 0.5),
                        m0_ltx().tex("\\color{white} m_b", 0),
                        m0_ltx().size.x(50, 0.2),
                    )
                )
            ),
            all(
                m0().position.x(0, 0.75),
                m1().position.x(0, 0.75), // make sure m1 follows for later
            ),
            waitFor(timing(descsegments[7]) - 2.5),
        )
    )

    yield* all(
        text().text(descsegments[8], 0.5),
        delay(timing(descsegments[8]) - 1,
            text().text(descsegments[9], 0.5),
        )
    )

    yield* waitFor(timing(descsegments[9]) - timing(descsegments[8]))

    yield* all(
        text().text(descsegments[10], 0.5),
        delay(0.75,
            all(
                m0().position.x(-100, 0.5),
                m1().position.x(100, 0.5),
                m1().opacity(1, 0.5),
                
                m0_ltx().tex("\\color{white} m_0 ?", 0.5),
                m0_ltx().size.x(60, 0.5),
                m1_ltx().tex("\\color{white} m_1 ?", 0.5),
                m1_ltx().size.x(60, 0.5),

                delay(0.75,
                    chain(
                        m0().position.y(170, 0.4).to(200, 0.4),
                        m1().position.y(170, 0.4).to(200, 0.4),
                    )
                )
            )
        ),
    )

    yield* waitFor(timing(descsegments[10]) - 2.5);

    yield* text().text(descsegments[11], 0.5),

    yield* waitFor(timing(descsegments[11]) - 1);

    yield* visual().opacity(0, 0.5);
    yield* text().opacity(0, 0.5);
    // END SCENE
});