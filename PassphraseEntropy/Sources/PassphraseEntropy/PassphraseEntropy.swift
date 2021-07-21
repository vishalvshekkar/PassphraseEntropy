import Foundation

struct PassphraseEntropy {

    private let allowedCharacterPools: Set<AllowedCharacters>
    private let guessesPerSecond = 100_000_000_000.0
    private var allCharacters: String {
        return allowedCharacterPools.reduce("") { $0 + $1.characters }
    }
    private var totalCharactersPoolCount: Int {
        return allCharacters.count
    }

    init(allowedCharacterPools: Set<AllowedCharacters>) {
        self.allowedCharacterPools = allowedCharacterPools
    }

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

        var characterPoolsUsed = Set<AllowedCharacters>()
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

    private func computeSearchSpaceSize(with passphraseLength: Int) -> Double {
        var searchSpaceSize = 0.0
        for loopIndex in 1..<passphraseLength {
            searchSpaceSize += pow(Double(passphraseLength), Double(loopIndex))
        }
        return searchSpaceSize
    }

    enum AllowedCharacters: Hashable {

        case uppercaseLetters
        case lowercaseLetters
        case numbers
        case symbols
        case space
        case custom(String)

        var characterSet: CharacterSet {
            return CharacterSet(charactersIn: characters)
        }

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

        var characterCount: Int {
            return characters.count
        }

        func getUniqueCharacterSet(from text: String) -> String {
            return String(Set(text))
        }

        func hash(into hasher: inout Hasher) {
            hasher.combine(characters)
        }

    }

    struct PassphraseAnalysisResult {

        let totalAllowedCharacters: String
        let totalAllowedCharactersCount: Int
        let passphrase: String
        let passphraseLength: Int
        let bitsOfEntropyPerCharacter: Double
        let bitsOfEntropy: Double
        let searchSpaceSize: Double
        let guessPerSecond: Double
        let timeTaken: Double

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

    }

}
