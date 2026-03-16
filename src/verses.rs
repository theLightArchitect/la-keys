use rand::seq::SliceRandom;

/// A curated Bible verse from the 1611 King James Version.
/// Each verse serves as the HKDF `info` parameter during key derivation,
/// making it a cryptographic component of the key's identity.
#[derive(Debug, Clone)]
pub struct Verse {
    pub reference: &'static str,
    pub text: &'static str,
    pub doctrine: &'static str,
}

/// Select a random verse from the curated collection.
#[must_use]
pub fn random_verse() -> &'static Verse {
    VERSES
        .choose(&mut rand::thread_rng())
        .expect("VERSES is non-empty")
}

/// Get a verse by its reference string (e.g., "John 3:16").
#[must_use]
pub fn find_verse(reference: &str) -> Option<&'static Verse> {
    VERSES.iter().find(|v| v.reference == reference)
}

/// The HKDF info string for a verse — used in key derivation.
/// Combines the reference and text to create a unique context.
#[must_use]
pub fn verse_hkdf_info(verse: &Verse) -> String {
    format!("larc:v1:{}:{}", verse.reference, verse.text)
}

// ─── Curated Verse Collection (1611 KJV) ──────────────────────────────────────
//
// Covering the critical doctrines shared across Protestant and Orthodox Christianity:
//   1. Trinity & Nature of God
//   2. Deity and Lordship of Christ
//   3. Virgin Birth & Incarnation
//   4. Atonement & Redemption
//   5. Resurrection
//   6. Salvation by Grace through Faith
//   7. Authority & Sufficiency of Scripture
//   8. Second Coming & Eschatology
//   9. Creation & Sovereignty
//  10. The Holy Spirit
//  11. The Church & Fellowship
//  12. Sanctification & Holiness
//  13. Providence & Faithfulness
//  14. Love & Commandments
//  15. Prayer & Worship
//  16. Wisdom & Knowledge
//  17. Spiritual Warfare & Protection

static VERSES: &[Verse] = &[
    // ── 1. Trinity & Nature of God ────────────────────────────────────────
    Verse {
        reference: "Genesis 1:1",
        text: "In the beginning God created the heaven and the earth.",
        doctrine: "creation",
    },
    Verse {
        reference: "Deuteronomy 6:4",
        text: "Heare, O Israel: The LORD our God is one LORD.",
        doctrine: "trinity",
    },
    Verse {
        reference: "Isaiah 6:3",
        text: "Holy, holy, holy is the LORD of hostes: the whole earth is full of his glory.",
        doctrine: "trinity",
    },
    Verse {
        reference: "Matthew 28:19",
        text: "Go ye therefore and teach all nations, baptizing them in the Name of the Father, and of the Sonne, and of the holy Ghost.",
        doctrine: "trinity",
    },
    Verse {
        reference: "2 Corinthians 13:14",
        text: "The grace of the Lord Iesus Christ, and the loue of God, and the communion of the holy Ghost, be with you all. Amen.",
        doctrine: "trinity",
    },
    Verse {
        reference: "1 John 5:7",
        text: "For there are three that beare record in heauen, the Father, the Word, and the holy Ghost: and these three are one.",
        doctrine: "trinity",
    },
    Verse {
        reference: "Exodus 3:14",
        text: "And God said vnto Moses, I AM THAT I AM.",
        doctrine: "nature_of_god",
    },
    Verse {
        reference: "Psalm 90:2",
        text: "Before the mountaines were brought foorth, or euer thou hadst formed the earth and the world: euen from euerlasting to euerlasting thou art God.",
        doctrine: "nature_of_god",
    },
    Verse {
        reference: "Malachi 3:6",
        text: "For I am the LORD, I change not.",
        doctrine: "nature_of_god",
    },
    // ── 2. Deity and Lordship of Christ ───────────────────────────────────
    Verse {
        reference: "John 1:1",
        text: "In the beginning was the Word, & the Word was with God, and the Word was God.",
        doctrine: "deity_of_christ",
    },
    Verse {
        reference: "John 1:14",
        text: "And the Word was made flesh, and dwelt among vs (and wee beheld his glory, the glory as of the onely begotten of the Father) full of grace and trueth.",
        doctrine: "incarnation",
    },
    Verse {
        reference: "John 10:30",
        text: "I and my Father are one.",
        doctrine: "deity_of_christ",
    },
    Verse {
        reference: "John 14:6",
        text: "Iesus saith vnto him, I am the Way, the Trueth, and the Life: no man commeth vnto the Father but by mee.",
        doctrine: "deity_of_christ",
    },
    Verse {
        reference: "Colossians 1:16-17",
        text: "For by him were all things created that are in heauen, and that are in earth, visible and inuisible. And hee is before all things, and by him all things consist.",
        doctrine: "deity_of_christ",
    },
    Verse {
        reference: "Philippians 2:10-11",
        text: "That at the Name of Iesus euery knee should bow, of things in heauen, and things in earth, and things vnder the earth: And that euery tongue should confesse, that Iesus Christ is Lord.",
        doctrine: "lordship_of_christ",
    },
    Verse {
        reference: "Hebrews 1:3",
        text: "Who being the brightnesse of his glory, and the expresse image of his person, and vpholding all things by the word of his power.",
        doctrine: "deity_of_christ",
    },
    Verse {
        reference: "Revelation 1:8",
        text: "I am Alpha and Omega, the beginning and the ending, saith the Lord, which is, and which was, and which is to come, the Almightie.",
        doctrine: "deity_of_christ",
    },
    // ── 3. Virgin Birth & Incarnation ─────────────────────────────────────
    Verse {
        reference: "Isaiah 7:14",
        text: "Therefore the Lord himselfe shall giue you a signe: Behold, a virgine shall conceiue and beare a sonne, and shall call his name Immanuel.",
        doctrine: "virgin_birth",
    },
    Verse {
        reference: "Luke 1:35",
        text: "The holy Ghost shall come vpon thee, and the power of the Highest shall ouershadow thee. Therefore also that holy thing which shall bee borne of thee, shall be called the Sonne of God.",
        doctrine: "virgin_birth",
    },
    // ── 4. Atonement & Redemption ─────────────────────────────────────────
    Verse {
        reference: "Isaiah 53:5",
        text: "But hee was wounded for our transgressions, hee was bruised for our iniquities: the chastisement of our peace was vpon him, and with his stripes we are healed.",
        doctrine: "atonement",
    },
    Verse {
        reference: "John 3:16",
        text: "For God so loued the world, that he gaue his only begotten Sonne: that whosoeuer beleeueth in him, should not perish, but haue euerlasting life.",
        doctrine: "atonement",
    },
    Verse {
        reference: "Romans 5:8",
        text: "But God commendeth his loue towards vs, in that while wee were yet sinners, Christ died for vs.",
        doctrine: "atonement",
    },
    Verse {
        reference: "1 Peter 2:24",
        text: "Who his owne selfe bare our sinnes in his owne body on the tree, that wee being dead to sinnes, should liue vnto righteousnesse: by whose stripes ye were healed.",
        doctrine: "atonement",
    },
    Verse {
        reference: "1 John 2:2",
        text: "And hee is the propitiation for our sinnes: and not for ours onely, but also for the sinnes of the whole world.",
        doctrine: "atonement",
    },
    Verse {
        reference: "Hebrews 9:22",
        text: "And almost all things are by the Law purged with blood: and without shedding of blood is no remission.",
        doctrine: "atonement",
    },
    // ── 5. Resurrection ───────────────────────────────────────────────────
    Verse {
        reference: "1 Corinthians 15:3-4",
        text: "Christ died for our sinnes according to the Scriptures. And that he was buried, and that he rose againe the third day according to the Scriptures.",
        doctrine: "resurrection",
    },
    Verse {
        reference: "Romans 6:9",
        text: "Knowing that Christ being raised from the dead, dieth no more: death hath no more dominion ouer him.",
        doctrine: "resurrection",
    },
    Verse {
        reference: "John 11:25",
        text: "Iesus said vnto her, I am the Resurrection, and the Life: hee that beleeueth in me, though he were dead, yet shall he liue.",
        doctrine: "resurrection",
    },
    // ── 6. Salvation by Grace through Faith ───────────────────────────────
    Verse {
        reference: "Ephesians 2:8-9",
        text: "For by grace are ye saued, through faith, and that not of your selues: it is the gift of God: Not of workes, lest any man should boast.",
        doctrine: "salvation",
    },
    Verse {
        reference: "Romans 3:23-24",
        text: "For all haue sinned, and come short of the glory of God, Being iustified freely by his grace, through the redemption that is in Christ Iesus.",
        doctrine: "salvation",
    },
    Verse {
        reference: "Romans 10:9",
        text: "That if thou shalt confesse with thy mouth the Lord Iesus, and shalt beleeue in thine heart, that God hath raised him from the dead, thou shalt be saued.",
        doctrine: "salvation",
    },
    Verse {
        reference: "Titus 3:5",
        text: "Not by workes of righteousnesse, which wee haue done, but according to his mercie he saued vs, by the washing of regeneration, and renewing of the holy Ghost.",
        doctrine: "salvation",
    },
    Verse {
        reference: "Acts 4:12",
        text: "Neither is there saluation in any other: for there is none other Name vnder heauen giuen among men whereby we must be saued.",
        doctrine: "salvation",
    },
    // ── 7. Authority & Sufficiency of Scripture ───────────────────────────
    Verse {
        reference: "2 Timothy 3:16",
        text: "All Scripture is giuen by inspiration of God, & is profitable for doctrine, for reproofe, for correction, for instruction in righteousnesse.",
        doctrine: "scripture",
    },
    Verse {
        reference: "Psalm 119:105",
        text: "Thy word is a lampe vnto my feete: and a light vnto my path.",
        doctrine: "scripture",
    },
    Verse {
        reference: "Isaiah 40:8",
        text: "The grasse withereth, the floure fadeth: but the word of our God shall stand for euer.",
        doctrine: "scripture",
    },
    Verse {
        reference: "Hebrews 4:12",
        text: "For the word of God is quicke and powerfull, and sharper then any two edged sword.",
        doctrine: "scripture",
    },
    // ── 8. Second Coming & Eschatology ────────────────────────────────────
    Verse {
        reference: "Acts 1:11",
        text: "This same Iesus which is taken vp from you into heauen, shall so come in like maner, as yee haue seene him goe into heauen.",
        doctrine: "second_coming",
    },
    Verse {
        reference: "Revelation 22:20",
        text: "He which testifieth these things, saith, Surely, I come quickly. Amen. Euen so, Come Lord Iesus.",
        doctrine: "second_coming",
    },
    Verse {
        reference: "1 Thessalonians 4:16-17",
        text: "For the Lord himselfe shall descend from heauen with a shout, with the voyce of the Archangell, and with the trumpe of God: and the dead in Christ shall rise first.",
        doctrine: "second_coming",
    },
    // ── 9. Creation & Sovereignty ─────────────────────────────────────────
    Verse {
        reference: "Psalm 24:1",
        text: "The earth is the LORDs, and the fulnesse thereof: the world, and they that dwell therein.",
        doctrine: "sovereignty",
    },
    Verse {
        reference: "Romans 8:28",
        text: "And we know that all things worke together for good, to them that loue God, to them who are the called according to his purpose.",
        doctrine: "sovereignty",
    },
    Verse {
        reference: "Proverbs 19:21",
        text: "There are many deuices in a mans heart: neuerthelesse the counsell of the LORD, that shall stand.",
        doctrine: "sovereignty",
    },
    // ── 10. The Holy Spirit ───────────────────────────────────────────────
    Verse {
        reference: "John 14:26",
        text: "But the Comforter, which is the holy Ghost, whom the Father will send in my Name, hee shall teach you all things.",
        doctrine: "holy_spirit",
    },
    Verse {
        reference: "Acts 2:4",
        text: "And they were all filled with the holy Ghost, and began to speake with other tongues, as the Spirit gaue them vtterance.",
        doctrine: "holy_spirit",
    },
    Verse {
        reference: "Romans 8:14",
        text: "For as many as are led by the Spirit of God, they are the sonnes of God.",
        doctrine: "holy_spirit",
    },
    Verse {
        reference: "Galatians 5:22-23",
        text: "But the fruit of the Spirit is loue, ioy, peace, long suffering, gentlenesse, goodnesse, faith, Meekenesse, temperance: against such there is no law.",
        doctrine: "holy_spirit",
    },
    // ── 11. The Church & Fellowship ───────────────────────────────────────
    Verse {
        reference: "Matthew 16:18",
        text: "Thou art Peter, and vpon this rocke I will build my Church: and the gates of hell shall not preuaile against it.",
        doctrine: "church",
    },
    Verse {
        reference: "1 Corinthians 12:27",
        text: "Now ye are the body of Christ, and members in particular.",
        doctrine: "church",
    },
    Verse {
        reference: "Hebrews 10:25",
        text: "Not forsaking the assembling of our selues together, as the maner of some is: but exhorting one another.",
        doctrine: "church",
    },
    // ── 12. Sanctification & Holiness ─────────────────────────────────────
    Verse {
        reference: "1 Peter 1:15-16",
        text: "But as he which hath called you is holy, so be yee holy in all maner of conuersation. Because it is written, Be yee holy, for I am holy.",
        doctrine: "sanctification",
    },
    Verse {
        reference: "Romans 12:1-2",
        text: "I beseech you therefore brethren, by the mercies of God, that yee present your bodies a liuing sacrifice, holy, acceptable vnto God, which is your reasonable seruice.",
        doctrine: "sanctification",
    },
    // ── 13. Providence & Faithfulness ─────────────────────────────────────
    Verse {
        reference: "Lamentations 3:22-23",
        text: "It is of the LORDs mercies that wee are not consumed, because his compassions faile not. They are new euery morning: great is thy faithfulnesse.",
        doctrine: "faithfulness",
    },
    Verse {
        reference: "Psalm 23:1",
        text: "The LORD is my shepheard, I shall not want.",
        doctrine: "providence",
    },
    Verse {
        reference: "Psalm 46:1",
        text: "God is our refuge and strength: a very present helpe in trouble.",
        doctrine: "providence",
    },
    Verse {
        reference: "Joshua 1:9",
        text: "Haue not I commanded thee? Be strong, and of a good courage: be not afraid, neither be thou dismayed: for the LORD thy God is with thee, whithersoeuer thou goest.",
        doctrine: "providence",
    },
    Verse {
        reference: "Isaiah 41:10",
        text: "Feare thou not, for I am with thee: be not dismaid, for I am thy God: I will strengthen thee, yea I will helpe thee.",
        doctrine: "providence",
    },
    Verse {
        reference: "Jeremiah 29:11",
        text: "For I know the thoughts that I thinke towards you, saith the LORD, thoughts of peace, and not of euill, to giue you an expected end.",
        doctrine: "providence",
    },
    // ── 14. Love & Commandments ───────────────────────────────────────────
    Verse {
        reference: "John 13:34",
        text: "A new commandement I giue vnto you, that yee loue one another, as I haue loued you, that ye also loue one another.",
        doctrine: "love",
    },
    Verse {
        reference: "1 Corinthians 13:13",
        text: "And now abideth faith, hope, charitie, these three, but the greatest of these is charitie.",
        doctrine: "love",
    },
    Verse {
        reference: "Matthew 22:37-39",
        text: "Iesus said vnto him, Thou shalt loue the Lord thy God with all thy heart, and with all thy soule, and with all thy mind. And the second is like vnto it, Thou shalt loue thy neighbour as thy selfe.",
        doctrine: "love",
    },
    // ── 15. Prayer & Worship ──────────────────────────────────────────────
    Verse {
        reference: "Philippians 4:6-7",
        text: "Be carefull for nothing: but in euery thing by prayer and supplication with thankesgiuing, let your requests be made knowen vnto God. And the peace of God which passeth all vnderstanding, shall keepe your hearts and mindes through Christ Iesus.",
        doctrine: "prayer",
    },
    Verse {
        reference: "John 4:24",
        text: "God is a Spirit, and they that worship him, must worship him in Spirit and in trueth.",
        doctrine: "worship",
    },
    Verse {
        reference: "Psalm 100:4",
        text: "Enter into his gates with thankesgiuing, and into his courts with praise: be thankfull vnto him, and blesse his Name.",
        doctrine: "worship",
    },
    // ── 16. Wisdom & Knowledge ────────────────────────────────────────────
    Verse {
        reference: "Proverbs 3:5-6",
        text: "Trust in the LORD with all thine heart: and leane not vnto thine owne vnderstanding. In all thy wayes acknowledge him, and he shall direct thy pathes.",
        doctrine: "wisdom",
    },
    Verse {
        reference: "James 1:5",
        text: "If any of you lacke wisedome, let him aske of God, that giueth to all men liberally, and vpbraideth not: and it shall be giuen him.",
        doctrine: "wisdom",
    },
    Verse {
        reference: "Proverbs 9:10",
        text: "The feare of the LORD is the beginning of wisedome: and the knowledge of the Holy is vnderstanding.",
        doctrine: "wisdom",
    },
    // ── 17. Spiritual Warfare & Protection ────────────────────────────────
    Verse {
        reference: "Ephesians 6:11",
        text: "Put on the whole armour of God, that ye may be able to stand against the wiles of the deuill.",
        doctrine: "spiritual_warfare",
    },
    Verse {
        reference: "Psalm 91:11",
        text: "For hee shall giue his Angels charge ouer thee, to keepe thee in all thy wayes.",
        doctrine: "protection",
    },
    Verse {
        reference: "Romans 8:37",
        text: "Nay in all these things wee are more then conquerours, through him that loued vs.",
        doctrine: "spiritual_warfare",
    },
    Verse {
        reference: "2 Timothy 1:7",
        text: "For God hath not giuen vs the spirit of feare, but of power, and of loue, and of a sound minde.",
        doctrine: "spiritual_warfare",
    },
    Verse {
        reference: "Isaiah 54:17",
        text: "No weapon that is formed against thee, shall prosper.",
        doctrine: "protection",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verse_count() {
        assert!(
            VERSES.len() >= 60,
            "should have at least 60 curated verses, got {}",
            VERSES.len()
        );
    }

    #[test]
    fn test_no_duplicate_references() {
        let mut refs: Vec<&str> = VERSES.iter().map(|v| v.reference).collect();
        refs.sort_unstable();
        let unique_count = refs.len();
        refs.dedup();
        assert_eq!(refs.len(), unique_count, "duplicate verse references found");
    }

    #[test]
    fn test_random_verse_returns_valid() {
        let verse = random_verse();
        assert!(!verse.reference.is_empty());
        assert!(!verse.text.is_empty());
        assert!(!verse.doctrine.is_empty());
    }

    #[test]
    fn test_find_verse() {
        assert!(find_verse("John 3:16").is_some());
        assert!(find_verse("Lamentations 3:22-23").is_some());
        assert!(find_verse("Not A Real Verse 99:99").is_none());
    }

    #[test]
    fn test_hkdf_info_format() {
        let verse = find_verse("John 1:1").expect("John 1:1 should exist");
        let info = verse_hkdf_info(verse);
        assert!(info.starts_with("larc:v1:John 1:1:"));
    }

    #[test]
    fn test_all_doctrines_covered() {
        let doctrines: std::collections::HashSet<&str> =
            VERSES.iter().map(|v| v.doctrine).collect();

        let required = [
            "trinity",
            "deity_of_christ",
            "virgin_birth",
            "atonement",
            "resurrection",
            "salvation",
            "scripture",
            "second_coming",
            "sovereignty",
            "holy_spirit",
            "church",
            "sanctification",
            "faithfulness",
            "love",
            "wisdom",
            "spiritual_warfare",
            "protection",
        ];

        for d in &required {
            assert!(doctrines.contains(d), "missing doctrine: {d}");
        }
    }
}
