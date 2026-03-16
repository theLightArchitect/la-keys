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
    // ── 18. The "I AM" Statements of Jesus ────────────────────────────────
    Verse {
        reference: "John 6:35",
        text: "And Iesus said vnto them, I am the bread of life: hee that commeth to me, shall neuer hunger: and he that beleeueth on me, shall neuer thirst.",
        doctrine: "i_am_statements",
    },
    Verse {
        reference: "John 8:12",
        text: "Then spake Iesus againe vnto them, saying, I am the light of the world: he that followeth me, shall not walke in darknesse, but shall haue the light of life.",
        doctrine: "i_am_statements",
    },
    Verse {
        reference: "John 8:58",
        text: "Iesus said vnto them, Uerily, verily I say vnto you, before Abraham was, I am.",
        doctrine: "i_am_statements",
    },
    Verse {
        reference: "John 10:9",
        text: "I am the doore: by me if any man enter in, hee shall be saued, and shall goe in and out, and find pasture.",
        doctrine: "i_am_statements",
    },
    Verse {
        reference: "John 10:11",
        text: "I am the good shepheard: the good shepheard giueth his life for the sheepe.",
        doctrine: "i_am_statements",
    },
    Verse {
        reference: "John 10:14",
        text: "I am the good shepheard, and know my sheepe, and am knowen of mine.",
        doctrine: "i_am_statements",
    },
    Verse {
        reference: "John 15:1",
        text: "I am the true vine, and my Father is the husbandman.",
        doctrine: "i_am_statements",
    },
    Verse {
        reference: "John 15:5",
        text: "I am the vine, yee are the branches: he that abideth in me, and I in him, the same bringeth forth much fruit: for without me ye can doe nothing.",
        doctrine: "i_am_statements",
    },
    // ── 19. Words and Teachings of Jesus ───────────────────────────────────
    Verse {
        reference: "Matthew 5:14",
        text: "Ye are the light of the world. A citie that is set on an hill, cannot be hid.",
        doctrine: "teachings_of_jesus",
    },
    Verse {
        reference: "Matthew 5:44",
        text: "But I say vnto you, Loue your enemies, blesse them that curse you, doe good to them that hate you, and pray for them which despitefully vse you, and persecute you.",
        doctrine: "teachings_of_jesus",
    },
    Verse {
        reference: "Matthew 6:33",
        text: "But seeke ye first the kingdome of God, and his righteousnesse, and all these things shall be added vnto you.",
        doctrine: "teachings_of_jesus",
    },
    Verse {
        reference: "Matthew 7:7",
        text: "Aske, and it shall be giuen you: seeke, and ye shall finde: knocke, and it shall be opened vnto you.",
        doctrine: "teachings_of_jesus",
    },
    Verse {
        reference: "Matthew 11:28",
        text: "Come vnto me all ye that labour, and are heauy laden, and I will giue you rest.",
        doctrine: "teachings_of_jesus",
    },
    Verse {
        reference: "Matthew 11:29",
        text: "Take my yoke vpon you, and learne of me, for I am meeke and lowly in heart: and ye shall find rest vnto your soules.",
        doctrine: "teachings_of_jesus",
    },
    Verse {
        reference: "Matthew 18:20",
        text: "For where two or three are gathered together in my Name, there am I in the midst of them.",
        doctrine: "teachings_of_jesus",
    },
    Verse {
        reference: "Matthew 28:20",
        text: "Teaching them to obserue all things, whatsoeuer I haue commanded you: and loe, I am with you alway, euen vnto the end of the world. Amen.",
        doctrine: "teachings_of_jesus",
    },
    Verse {
        reference: "Mark 10:45",
        text: "For euen the Sonne of man came not to be ministred vnto, but to minister, and to giue his life a ransome for many.",
        doctrine: "teachings_of_jesus",
    },
    Verse {
        reference: "Luke 19:10",
        text: "For the Sonne of man is come to seeke, and to saue that which was lost.",
        doctrine: "teachings_of_jesus",
    },
    Verse {
        reference: "John 3:3",
        text: "Iesus answered, and said vnto him, Uerily, verily I say vnto thee, except a man be borne againe, he cannot see the kingdome of God.",
        doctrine: "teachings_of_jesus",
    },
    Verse {
        reference: "John 4:14",
        text: "But whosoeuer drinketh of the water that I shall giue him, shall neuer thirst: but the water that I shall giue him, shalbe in him a well of water springing vp into euerlasting life.",
        doctrine: "teachings_of_jesus",
    },
    Verse {
        reference: "John 5:24",
        text: "Uerily, verily I say vnto you, he that heareth my word, and beleeueth on him that sent mee, hath euerlasting life, and shall not come into condemnation: but is passed from death vnto life.",
        doctrine: "teachings_of_jesus",
    },
    Verse {
        reference: "John 6:47",
        text: "Uerily, verily I say vnto you, he that beleeueth on me, hath euerlasting life.",
        doctrine: "teachings_of_jesus",
    },
    Verse {
        reference: "John 8:32",
        text: "And ye shall know the Trueth, and the Trueth shall make you free.",
        doctrine: "teachings_of_jesus",
    },
    Verse {
        reference: "John 8:36",
        text: "If the Sonne therefore shall make you free, ye shall be free indeed.",
        doctrine: "teachings_of_jesus",
    },
    Verse {
        reference: "John 10:27-28",
        text: "My sheepe heare my voyce, and I know them, and they follow me. And I giue vnto them eternall life, and they shall neuer perish, neither shall any man plucke them out of my hand.",
        doctrine: "teachings_of_jesus",
    },
    Verse {
        reference: "John 12:46",
        text: "I am come a light into the world, that whosoeuer beleeueth on mee, should not abide in darkenesse.",
        doctrine: "teachings_of_jesus",
    },
    Verse {
        reference: "John 14:1-2",
        text: "Let not your heart be troubled: ye beleeue in God, beleeue also in me. In my Fathers house are many mansions; if it were not so, I would haue told you: I goe to prepare a place for you.",
        doctrine: "teachings_of_jesus",
    },
    Verse {
        reference: "John 14:27",
        text: "Peace I leaue with you, my peace I giue vnto you: not as the world giueth, giue I vnto you. Let not your heart bee troubled, neither let it bee afraid.",
        doctrine: "teachings_of_jesus",
    },
    Verse {
        reference: "John 16:33",
        text: "These things I haue spoken vnto you, that in me ye might haue peace. In the world ye shall haue tribulation: but be of good cheere, I haue ouercome the world.",
        doctrine: "teachings_of_jesus",
    },
    // ── 20. Messianic Prophecies Fulfilled in Jesus ───────────────────────
    Verse {
        reference: "Isaiah 9:6",
        text: "For vnto vs a child is borne, vnto vs a Sonne is giuen, and the gouernment shall be vpon his shoulder: and his Name shalbe called, Wonderfull, Counsellor, The mightie God, The euerlasting Father, The Prince of peace.",
        doctrine: "messianic_prophecy",
    },
    Verse {
        reference: "Micah 5:2",
        text: "But thou Bethlehem Ephratah, though thou be little among the thousands of Iudah, yet out of thee shall he come foorth vnto mee, that is to bee ruler in Israel: whose goings foorth haue bene from of old, from euerlasting.",
        doctrine: "messianic_prophecy",
    },
    Verse {
        reference: "Isaiah 53:3",
        text: "He is despised and reiected of men, a man of sorrowes, and acquainted with griefe: and wee hid as it were our faces from him; he was despised and we esteemed him not.",
        doctrine: "messianic_prophecy",
    },
    Verse {
        reference: "Isaiah 53:7",
        text: "He was oppressed, and he was afflicted, yet hee opened not his mouth: hee is brought as a lambe to the slaughter, and as a sheepe before her shearers is dumme, so he openeth not his mouth.",
        doctrine: "messianic_prophecy",
    },
    Verse {
        reference: "Psalm 22:16",
        text: "For dogges haue compassed me: the assembly of the wicked haue inclosed me: they pierced my hands and my feete.",
        doctrine: "messianic_prophecy",
    },
    Verse {
        reference: "Psalm 22:18",
        text: "They part my garments among them: and cast lots vpon my vesture.",
        doctrine: "messianic_prophecy",
    },
    Verse {
        reference: "Zechariah 9:9",
        text: "Reioyce greatly, O daughter of Zion; shout, O daughter of Ierusalem: behold, thy King commeth vnto thee: he is iust, and hauing saluation, lowly, and riding vpon an asse.",
        doctrine: "messianic_prophecy",
    },
    Verse {
        reference: "Psalm 16:10",
        text: "For thou wilt not leaue my soule in hell: neither wilt thou suffer thine Holy one to see corruption.",
        doctrine: "messianic_prophecy",
    },
    Verse {
        reference: "Daniel 7:13-14",
        text: "I saw in the night visions, and behold, one like the Sonne of man came with the clouds of heauen. And there was giuen him dominion, and glory, and a kingdome, that all people, nations and languages should serue him.",
        doctrine: "messianic_prophecy",
    },
    Verse {
        reference: "Isaiah 11:1-2",
        text: "And there shall come foorth a rod out of the stemme of Iesse, and a branch shall grow out of his rootes. And the Spirit of the LORD shall rest vpon him.",
        doctrine: "messianic_prophecy",
    },
    // ── 21. The Cross and Passion of Christ ───────────────────────────────
    Verse {
        reference: "Matthew 27:46",
        text: "And about the ninth houre, Iesus cryed with a loud voyce, saying, Eli, Eli, Lama sabachthani, that is to say, My God, my God, why hast thou forsaken mee?",
        doctrine: "passion_of_christ",
    },
    Verse {
        reference: "Luke 23:34",
        text: "Then saide Iesus, Father, forgiue them, for they know not what they doe.",
        doctrine: "passion_of_christ",
    },
    Verse {
        reference: "Luke 23:43",
        text: "And Iesus said vnto him, Uerily, I say vnto thee, to day shalt thou be with me in Paradise.",
        doctrine: "passion_of_christ",
    },
    Verse {
        reference: "John 19:30",
        text: "When Iesus therefore had receiued the vineger, hee said, It is finished: and he bowed his head, and gaue vp the ghost.",
        doctrine: "passion_of_christ",
    },
    Verse {
        reference: "Luke 23:46",
        text: "And when Iesus had cryed with a loud voyce, hee said, Father, into thy hands I commend my spirit: and hauing said thus, he gaue vp the ghost.",
        doctrine: "passion_of_christ",
    },
    Verse {
        reference: "Galatians 2:20",
        text: "I am crucified with Christ: neuerthelesse I liue, yet not I, but Christ liueth in me: and the life which I now liue in the flesh, I liue by the faith of the Sonne of God, who loued me, and gaue himselfe for me.",
        doctrine: "passion_of_christ",
    },
    Verse {
        reference: "Romans 6:23",
        text: "For the wages of sinne is death: but the gift of God is eternall life, through Iesus Christ our Lord.",
        doctrine: "passion_of_christ",
    },
    // ── 22. Resurrection Appearances and Power ────────────────────────────
    Verse {
        reference: "Matthew 28:5-6",
        text: "And the Angel answered, and said vnto the women, Feare not ye: for I know that ye seeke Iesus, which was crucified. He is not here: for he is risen, as hee said.",
        doctrine: "resurrection_of_jesus",
    },
    Verse {
        reference: "Luke 24:6",
        text: "He is not here, but is risen.",
        doctrine: "resurrection_of_jesus",
    },
    Verse {
        reference: "John 20:27-28",
        text: "Then saith he to Thomas, Reach hither thy finger, and behold my hands, and reach hither thy hand, and thrust it into my side, and be not faithlesse, but beleeuing. And Thomas answered, and said vnto him, My Lord, and my God.",
        doctrine: "resurrection_of_jesus",
    },
    Verse {
        reference: "1 Corinthians 15:20",
        text: "But now is Christ risen from the dead, and become the first fruits of them that slept.",
        doctrine: "resurrection_of_jesus",
    },
    Verse {
        reference: "1 Corinthians 15:55-57",
        text: "O death, where is thy sting? O graue, where is thy victorie? The sting of death is sinne: and the strength of sinne is the Law. But thankes be to God, which giueth vs the victorie, through our Lord Iesus Christ.",
        doctrine: "resurrection_of_jesus",
    },
    Verse {
        reference: "Philippians 3:10",
        text: "That I may know him, and the power of his resurrection, and the fellowship of his sufferings, being made conformable vnto his death.",
        doctrine: "resurrection_of_jesus",
    },
    // ── 23. Jesus as High Priest and Mediator ─────────────────────────────
    Verse {
        reference: "1 Timothy 2:5",
        text: "For there is one God, and one Mediatour betweene God and men, the man Christ Iesus.",
        doctrine: "jesus_mediator",
    },
    Verse {
        reference: "Hebrews 4:14-15",
        text: "Seeing then that wee haue a great high Priest, that is passed into the heauens, Iesus the Sonne of God, let vs hold fast our profession. For wee haue not an high Priest which cannot bee touched with the feeling of our infirmities: but was in all points tempted like as wee are, yet without sinne.",
        doctrine: "jesus_mediator",
    },
    Verse {
        reference: "Hebrews 7:25",
        text: "Wherefore hee is able also to saue them to the vttermost, that come vnto God by him, seeing he euer liueth to make intercession for them.",
        doctrine: "jesus_mediator",
    },
    Verse {
        reference: "Romans 8:34",
        text: "Who is hee that condemneth? It is Christ that died, yea rather that is risen againe, who is euen at the right hand of God, who also maketh intercession for vs.",
        doctrine: "jesus_mediator",
    },
    Verse {
        reference: "Hebrews 12:2",
        text: "Looking vnto Iesus the authour and finisher of our faith, who for the ioy that was set before him, endured the crosse, despising the shame, and is set downe at the right hand of the throne of God.",
        doctrine: "jesus_mediator",
    },
    // ── 24. Jesus as King and Lord ────────────────────────────────────────
    Verse {
        reference: "Revelation 19:16",
        text: "And he hath on his vesture, and on his thigh a name written, KING OF KINGS, AND LORD OF LORDS.",
        doctrine: "jesus_king",
    },
    Verse {
        reference: "Revelation 5:12",
        text: "Saying with a loud voyce, Worthy is the Lambe that was slaine, to receiue power, and riches, and wisedome, and strength, and honour, and glory, and blessing.",
        doctrine: "jesus_king",
    },
    Verse {
        reference: "Matthew 28:18",
        text: "And Iesus came, and spake vnto them, saying, All power is giuen vnto me in heauen and in earth.",
        doctrine: "jesus_king",
    },
    Verse {
        reference: "1 Timothy 6:15",
        text: "Which in his times hee shall shew, who is the blessed and onely Potentate, the King of kings, and Lord of lords.",
        doctrine: "jesus_king",
    },
    Verse {
        reference: "Acts 2:36",
        text: "Therefore let all the house of Israel know assuredly, that God hath made that same Iesus whom ye haue crucified, both Lord and Christ.",
        doctrine: "jesus_king",
    },
    // ── 25. The Lamb of God ───────────────────────────────────────────────
    Verse {
        reference: "John 1:29",
        text: "The next day Iohn seeth Iesus comming vnto him, and saith, Behold the Lambe of God, which taketh away the sinne of the world.",
        doctrine: "lamb_of_god",
    },
    Verse {
        reference: "Revelation 5:5-6",
        text: "And one of the Elders saith vnto me, Weepe not: behold, the Lyon of the tribe of Iuda, the roote of Dauid, hath preuailed to open the booke. And I beheld, and loe, in the midst of the throne stood a Lambe, as it had beene slaine.",
        doctrine: "lamb_of_god",
    },
    Verse {
        reference: "1 Peter 1:18-19",
        text: "Forasmuch as ye know that yee were not redeemed with corruptible things, as siluer and golde, but with the precious blood of Christ, as of a Lambe without blemish and without spot.",
        doctrine: "lamb_of_god",
    },
    Verse {
        reference: "Revelation 7:17",
        text: "For the Lambe which is in the midst of the throne, shall feede them, and shall leade them vnto liuing fountaines of waters: and God shall wipe away all teares from their eyes.",
        doctrine: "lamb_of_god",
    },
    // ── 26. Jesus's Prayers ───────────────────────────────────────────────
    Verse {
        reference: "John 17:3",
        text: "And this is life eternall, that they might know thee the onely true God, and Iesus Christ whom thou hast sent.",
        doctrine: "jesus_prayers",
    },
    Verse {
        reference: "John 17:20-21",
        text: "Neither pray I for these alone, but for them also which shall beleeue on me through their word: That they all may bee one, as thou Father art in mee, and I in thee, that they also may be one in vs.",
        doctrine: "jesus_prayers",
    },
    // ── 27. Names and Titles of Jesus ─────────────────────────────────────
    Verse {
        reference: "Isaiah 9:6b",
        text: "And his Name shalbe called, Wonderfull, Counsellor, The mightie God, The euerlasting Father, The Prince of peace.",
        doctrine: "names_of_jesus",
    },
    Verse {
        reference: "Revelation 22:16",
        text: "I Iesus haue sent mine Angel, to testifie vnto you these things in the Churches. I am the roote and the offspring of Dauid, and the bright and morning starre.",
        doctrine: "names_of_jesus",
    },
    Verse {
        reference: "Matthew 1:23",
        text: "Behold, a virgine shalbe with child, and shall bring foorth a sonne, and they shall call his name Emmanuel, which being interpreted, is, God with vs.",
        doctrine: "names_of_jesus",
    },
    Verse {
        reference: "John 1:36",
        text: "And looking vpon Iesus as hee walked, hee saith, Behold the Lambe of God.",
        doctrine: "names_of_jesus",
    },
    Verse {
        reference: "Revelation 22:13",
        text: "I am Alpha and Omega, the beginning and the end, the first and the last.",
        doctrine: "names_of_jesus",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verse_count() {
        assert!(
            VERSES.len() >= 140,
            "should have at least 140 curated verses, got {}",
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
            "i_am_statements",
            "teachings_of_jesus",
            "messianic_prophecy",
            "passion_of_christ",
            "resurrection_of_jesus",
            "jesus_mediator",
            "jesus_king",
            "lamb_of_god",
            "names_of_jesus",
        ];

        for d in &required {
            assert!(doctrines.contains(d), "missing doctrine: {d}");
        }
    }
}
