function roundToPointFive(num: number) {
    return Math.round(num * 2) / 2;
}

// average reading speed is 3.5 words per second so i hope this is fine
// idk i read pretty fast (wow weird felx but ok)

/**
 * Return the nearest 0.5 second interval for reading the given text.
 * @param words The text to be read.
 * @returns The number of seconds to read the text.
*/
export function timing(words: string) {
    let wordsPerSecond = 6;
    let seconds = roundToPointFive((words.split(" ").length) / wordsPerSecond);
    // console.log(seconds); // debug
    return seconds;
}

