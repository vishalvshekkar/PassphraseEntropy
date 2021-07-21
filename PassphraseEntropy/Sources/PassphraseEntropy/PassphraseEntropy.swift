import Foundation

/// This structure analyzes a passphrase and gives the result that contains various information about the give passphrase including `bitsOfEntropy`.
struct PassphraseEntropy {

    /// A set that holds all the allows characters for your passphrase field.
    private let allowedCharacterPools: Set<AllowedCharacterPools>

    /// The passphrase brute force guess rate you want to compute the time to crack the passphrase with.
    private let guessesPerSecond = 100_000_000_000.0

    /// Gives a string containing all the allowed characters for the passphrase.
    private var allCharacters: String {
        return allowedCharacterPools.reduce("") { $0 + $1.characters }
    }

    /// Gives a count of all the allowed characters for the passphrase.
    private var totalCharactersPoolCount: Int {
        return allCharacters.count
    }

    /// Initializer for the structure.
    /// - Parameter allowedCharacterPools: The set of allowed character pools for this session of passphrase analysis.
    init(allowedCharacterPools: Set<AllowedCharacterPools>) {
        self.allowedCharacterPools = allowedCharacterPools
    }

    /// Invoke this function to analyze a given passphrase. The function returns an optional `PassphraseAnalysisResult`. This would be `nil` if the given passphrase was empty.
    /// - Parameter passphrase: The passphrase string to be analyzed.
    /// - Returns: An optional analysis result.
    func analyze(_ passphrase: String) -> PassphraseAnalysisResult? {
        guard !passphrase.isEmpty else {
            return nil
        }

        var characterPoolUsedInPassphrase = ""
        for character in allCharacters {
            if passphrase.contains(character) {
                characterPoolUsedInPassphrase.append(String(character))
            }
        }

        var characterPoolsUsed = Set<AllowedCharacterPools>()
        for characterPool in allowedCharacterPools {
            if passphrase.rangeOfCharacter(from: characterPool.characterSet) != nil {
                characterPoolsUsed.insert(characterPool)
            }
        }
        let characterPoolSize = characterPoolsUsed.reduce(0) { $0 + $1.characterCount }

        let passphraseLength = passphrase.count
        let bitsOfEntropyPerCharacter = log2(Double(characterPoolSize))
        let bitsOfEntropy = Double(passphraseLength) * bitsOfEntropyPerCharacter
        let searchSpaceSize = computeSearchSpaceSize(with: passphraseLength)
        let timeTaken = searchSpaceSize/guessesPerSecond
        return PassphraseAnalysisResult(
            totalAllowedCharacters: allCharacters,
            totalAllowedCharactersCount: totalCharactersPoolCount,
            passphrase: passphrase,
            passphraseLength: passphraseLength,
            bitsOfEntropyPerCharacter: bitsOfEntropyPerCharacter,
            bitsOfEntropy: bitsOfEntropy,
            searchSpaceSize: searchSpaceSize,
            guessPerSecond: guessesPerSecond,
            timeTaken: timeTaken
        )
    }

    /// This function computes the passphrase search space size. That is nothing but the total number of possible passphrases, given the length of the user's given passphrase, that would have to be tested to brute-force the system.
    /// - Parameter passphraseLength: The length of the given passphrase.
    /// - Returns: A `Double` value representing the search space.
    private func computeSearchSpaceSize(with passphraseLength: Int) -> Double {
        var searchSpaceSize = 0.0
        for loopIndex in 1..<passphraseLength {
            searchSpaceSize += pow(Double(passphraseLength), Double(loopIndex))
        }
        return searchSpaceSize
    }

    /// This enums holds all the allowed character pools. There is one custom type that accepts a `String`, the unique characters in which would be considered as the pool.
    enum AllowedCharacterPools: Hashable {

        /// All the 26 English upper case letters.
        /// ```
        /// ABCDEFGHIJKLMNOPQRSTUVWXYZ
        /// ```
        case uppercaseLetters

        /// All the 26 English lower case letters.
        /// ```
        /// abcdefghijklmnopqrstuvwxyz
        /// ```
        case lowercaseLetters

        /// All the 10 numerals.
        /// ```
        /// 1234567890
        /// ```
        case numbers

        /// A hand-picked selection of symbols.
        /// ```
        /// !\“#$%&‘()*+,-./:;<=>?@[\\]^_`{|}~
        /// ```
        case symbols

        /// The single whitespace character.
        case space

        /// A custom pool that you can define. A set of the characters in the given `String` would be sued as the pool. Repeated characters would be flattened. Use the prpoperties `characters` and `characterCount` to know what characters make it to the final cut.
        case custom(String)

        /// get a `CharacterSet` instance from the character pool.
        var characterSet: CharacterSet {
            return CharacterSet(charactersIn: characters)
        }

        /// Retruns a string with all the characters in the pool.
        var characters: String {
            switch self {
            case .uppercaseLetters:
                return "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            case .lowercaseLetters:
                return "abcdefghijklmnopqrstuvwxyz"
            case .numbers:
                return "1234567890"
            case .symbols:
                return "!\"#$%&‘()*+,-./:;<=>?@[\\]^_`{|}~"
            case .space:
                return " "
            case .custom(let text):
                return getUniqueCharacterSet(from: text)
            }
        }

        /// Retruns the count of all the characters in the pool.
        var characterCount: Int {
            return characters.count
        }

        /// Retruns a string with only the unique characters from the given string. Order of retruned string is not guaranteed.
        /// - Parameter text: String to process.
        /// - Returns: Output string with only unqiue characters.
        private func getUniqueCharacterSet(from text: String) -> String {
            return String(Set(text))
        }

        // The hash function implementation to conform to the `Hashable` protocol.
        func hash(into hasher: inout Hasher) {
            hasher.combine(characters)
        }

    }

    /// This structure holds the result attributes of the analysis done by the `analyze:passphrase` function.
    struct PassphraseAnalysisResult {

        /// All the characters allowed as per the pools set when initializing `PassphraseEntropy`.
        let totalAllowedCharacters: String

        /// The count of all the characters allowed as per the pools set when initializing `PassphraseEntropy`.
        let totalAllowedCharactersCount: Int

        /// Then analyzed passphrase.
        let passphrase: String

        /// Then analyzed passphrase length.
        let passphraseLength: Int

        /// Bits of entropy per character, derived from all the pools of characters the given passphrase contains. The higher this number, the more complex the passphrase is.
        let bitsOfEntropyPerCharacter: Double

        /// Bits of entropy for the entire passphrase. The higher this number, the more complex the passphrase is. This is the value one cares about. use this to determine how secure a given passphrase is.
        let bitsOfEntropy: Double

        /// The size of the search space, based on the length of the passphrase.
        let searchSpaceSize: Double

        /// The number of guesses per minute considered when computing time taken to crack a passphrase. The more power a machine/cluster would be, the higher this number would be.
        let guessPerSecond: Double

        /// The time taken to brute-force a passphrase. Represented in seconds.
        let timeTaken: Double

        /// A function to print the results in the console.
        func describe() {
            print("totalAllowedCharacters: \(totalAllowedCharacters)")
            print("totalAllowedCharactersCount: \(totalAllowedCharactersCount)")
            print("passphrase: \(passphrase)")
            print("passphraseLength: \(passphraseLength)")
            print("bitsOfEntropyPerCharacter: \(bitsOfEntropyPerCharacter)")
            print("bitsOfEntropy: \(bitsOfEntropy)")
            print("searchSpaceSize: \(searchSpaceSize)")
            print("guessPerSecond: \(guessPerSecond)")
            print("timeTaken: \(timeTaken)")
        }

        /// A function to compute `timeTaken` for a different `guessPerSecond` value than what was initially used when initializing `PassphraseEntropy`.
        /// - Parameter guessesPerSecond: The new value for the guesses per second you want to compute time for.
        /// - Returns: The time taken to crack the passphrase.
        func timeTaken(for guessesPerSecond: Double) -> Double {
            return searchSpaceSize/guessesPerSecond
        }

    }

}
