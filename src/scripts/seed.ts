#!/usr/bin/env node
/**
 * Seed script for testing the Web UI
 *
 * Creates multiple test pools with fake participants for browsing.
 * Demonstrates Rendezvous as a general-purpose mutual matching platform.
 * Some participants will select EVERYONE, so any new user who
 * joins and selects them will get mutual matches.
 *
 * Run with: npm run seed
 */

import {
  createRendezvous,
  generateKeypair,
  generateSigningKeypair,
} from '../rendezvous/index.js';
import { deriveMatchTokens, deriveMatchToken, deriveNullifier } from '../rendezvous/crypto.js';
import * as fs from 'fs';
import * as path from 'path';
import * as nodeCrypto from 'crypto';

// Helper to encrypt reveal data using match token as key (AES-256-GCM)
function encryptRevealData(data: { contact: string; message: string }, matchToken: string): string {
  const tokenBytes = Buffer.from(matchToken, 'hex');
  const key = tokenBytes.slice(0, 32);
  const iv = nodeCrypto.randomBytes(12);
  const cipher = nodeCrypto.createCipheriv('aes-256-gcm', key, iv);
  const plaintext = JSON.stringify(data);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  // Format: IV (12) + ciphertext + authTag (16)
  const result = Buffer.concat([iv, encrypted, authTag]);
  return result.toString('base64');
}

// Pool configurations with their participants
const SEED_POOLS = [
  {
    name: 'Friday Night Mixer',
    description: 'A fun social pool for meeting new people! Browse profiles and find your matches.',
    emoji: '🍸',
    participants: [
      { displayName: 'Bob Martinez', bio: 'Data scientist by day, amateur chef by night. Ask me about my sourdough starter.', selectsEveryone: true, contact: 'bob.martinez@email.com', message: 'Hey! Would love to grab coffee and chat about sourdough!' },
      { displayName: 'Carol Johnson', bio: 'Product designer with a passion for sustainable fashion. Dog mom to a corgi named Pixel.', selectsEveryone: true, contact: '@carol_designs', message: 'DM me on Twitter! Let\'s meet up with our dogs!' },
      { displayName: 'David Kim', bio: 'Startup founder in the climate tech space. Always down for a good board game night.', selectsEveryone: true, contact: 'david@climateco.io', message: 'Board game night this Friday? Let me know!' },
      { displayName: 'Emma Williams', bio: 'PhD student in neuroscience. I can talk about brains or recommend great sci-fi books.', contact: 'e.williams@university.edu' },
      { displayName: 'Frank Rodriguez', bio: 'Musician and music teacher. Currently learning jazz piano. Coffee enthusiast.', contact: '@frankmusic' },
      { displayName: 'Grace Liu', bio: 'UX researcher who travels for food. Currently obsessed with fermented everything.', contact: 'grace.liu@design.co' },
      { displayName: 'Henry Thompson', bio: 'Backend engineer at a fintech. Weekend rock climber and mediocre but enthusiastic cook.', contact: 'henry.t@proton.me' },
      { displayName: 'Iris Patel', bio: 'Marketing lead who writes poetry on the side. Firm believer that pineapple belongs on pizza.', contact: '@iris_writes' },
      { displayName: 'Jack O\'Brien', bio: 'Architect with a love for mid-century modern design. Amateur photographer of buildings.', contact: 'jack.obrien@arch.firm' },
      { displayName: 'Kate Nakamura', bio: 'Veterinarian specializing in exotic animals. My apartment is basically a small zoo.', contact: 'dr.kate@exoticvet.com' },
      { displayName: 'Leo Santos', bio: 'Freelance illustrator and comic book nerd. Working on my own graphic novel!', contact: '@leodrawsthings' },
      { displayName: 'Maya Gupta', bio: 'Environmental lawyer fighting the good fight. Yoga instructor on weekends.', contact: 'maya@greenlaw.org' },
      { displayName: 'Noah Fischer', bio: 'Game developer who still plays too many games. Competitive Smash Bros player.', contact: 'noah.fischer@gamedev.co' },
      { displayName: 'Olivia Brown', bio: 'ER nurse with dark humor. I knit to decompress. Will make you a scarf.', contact: 'olivia.b.rn@hospital.org' },
    ],
  },
  {
    name: 'YC W25 Co-Founder Match',
    description: 'Find your startup co-founder! Technical founders meet business minds. Mutual interest means aligned vision.',
    emoji: '🚀',
    participants: [
      { displayName: 'Alex Chen', bio: 'Ex-Google Staff Engineer, 12 years in ML/AI. Built recommendation systems serving 100M+ users. Looking for business co-founder for B2B AI startup.', selectsEveryone: true, contact: 'alex.chen@gmail.com', message: 'Let\'s grab coffee and discuss the AI opportunity!' },
      { displayName: 'Sarah Mitchell', bio: 'Former McKinsey, 5 years product at Stripe. Deep enterprise sales network. Need technical co-founder for fintech idea.', selectsEveryone: true, contact: 'sarah.m@linkedin.com', message: 'Happy to chat about the fintech space. Schedule via Calendly: calendly.com/sarah-m' },
      { displayName: 'James Park', bio: 'Serial founder, 2 exits (one to Amazon). Full-stack + growth. Looking for domain expert co-founder in healthcare or climate.', selectsEveryone: true, contact: 'james@parkventures.co', message: 'Always looking to meet great founders!' },
      { displayName: 'Priya Sharma', bio: 'Stanford CS PhD, published in NeurIPS. Research background in NLP. Want to commercialize my research with right partner.', contact: 'priya.sharma@stanford.edu' },
      { displayName: 'Marcus Johnson', bio: 'Ex-Airbnb engineering manager. Led teams of 20+. Looking for CEO-type to handle fundraising while I build.', contact: 'marcus.j@proton.me' },
      { displayName: 'Lisa Wang', bio: 'YC alum (W21), first startup acqui-hired. Ready for round two with technical co-founder. Focus: developer tools.', contact: '@lisaw_tech' },
      { displayName: 'Ryan O\'Connor', bio: '10 years enterprise sales at Salesforce. $50M+ closed. Want to start something in vertical SaaS.', contact: 'ryan.oconnor@salesforce-alum.com' },
      { displayName: 'Nina Patel', bio: 'Product designer turned PM at Meta. 8 years experience. Looking to join pre-seed as design-focused co-founder.', contact: 'nina.patel.design@gmail.com' },
      { displayName: 'Kevin Zhang', bio: 'Blockchain engineer, contributed to Ethereum. Want to build real utility in crypto with non-technical partner.', contact: '@kevinz_eth' },
      { displayName: 'Amanda Foster', bio: 'Healthcare operator, ran 3 clinics. MBA from Wharton. Looking for technical co-founder to fix healthcare billing.', contact: 'amanda.foster@wharton.edu' },
      { displayName: 'Derek Williams', bio: 'Backend specialist, Rust/Go. Built infra at Cloudflare. Interested in security or infrastructure startups.', contact: 'derek.w@cloudflare-alum.com' },
      { displayName: 'Michelle Torres', bio: 'Growth marketer, scaled 2 startups to Series B. Looking for technical founder who needs help with GTM.', contact: 'michelle@growthco.io' },
    ],
  },
  {
    name: 'HackTech 2025 Team Builder',
    description: 'Find teammates for the hackathon! Designers, developers, and product minds - match with complementary skills.',
    emoji: '💻',
    participants: [
      { displayName: 'Jordan Lee', bio: 'React/Next.js specialist, 4 years exp. Won 3 hackathons. Looking for backend dev and designer for AI project.', selectsEveryone: true, contact: 'jordan.lee@hackathon.dev', message: 'Let\'s win this thing! Discord: jordanlee#1234' },
      { displayName: 'Sam Rivera', bio: 'UI/UX designer, Figma expert. Shipped 15+ products. Want strong technical team that values design.', selectsEveryone: true, contact: '@samrivera_design', message: 'Check my portfolio: samrivera.design' },
      { displayName: 'Taylor Kim', bio: 'Full-stack (Python/TypeScript). ML experience with PyTorch. Open to any interesting project!', selectsEveryone: true, contact: 'taylor.kim.dev@gmail.com', message: 'Super flexible on project ideas!' },
      { displayName: 'Casey Morgan', bio: 'Backend dev, Go and Rust. Into systems programming. Looking for frontend dev for dev tools idea.', contact: 'casey@rustdev.io' },
      { displayName: 'Riley Chen', bio: 'Product manager at startup. Great at pitching and user research. Need technical teammates!', contact: 'riley.chen.pm@gmail.com' },
      { displayName: 'Avery Thompson', bio: 'iOS/Android developer. Built apps with 100k+ downloads. Looking for designer and backend dev.', contact: '@averymobile' },
      { displayName: 'Quinn Davis', bio: 'Data scientist, Python/SQL. Can do ML models and data viz. Looking for full-stack team.', contact: 'quinn.davis@datascience.co' },
      { displayName: 'Morgan Patel', bio: 'DevOps engineer. Can deploy anything anywhere. Looking for team that needs infra help.', contact: 'morgan@devops.ninja' },
      { displayName: 'Jamie Wilson', bio: 'Game dev (Unity/Unreal). Want to build something fun! Need artist and sound designer.', contact: '@jamiegamedev' },
      { displayName: 'Drew Martinez', bio: 'Blockchain/Web3 dev. Smart contracts in Solidity. Looking for frontend dev for DeFi project.', contact: 'drew@web3builders.eth' },
      { displayName: 'Skyler Brown', bio: 'Motion designer and illustrator. After Effects, Lottie animations. Want to join creative team.', contact: '@skylermotions' },
      { displayName: 'Reese Johnson', bio: 'Security researcher, CTF player. Want to build security tools. Need full-stack partner.', contact: 'reese@securityresearch.io' },
    ],
  },
  {
    name: 'SF Housing Search - Mission/Castro',
    description: 'Find compatible roommates! Mutual matching means both parties want to live together. No awkward rejections.',
    emoji: '🏠',
    participants: [
      { displayName: 'Chris Anderson', bio: 'Software engineer, 28. WFH 3 days/week. Clean, quiet, no parties. Cat-friendly? Budget: $2200/mo.', selectsEveryone: true, contact: 'chris.anderson@tech.co', message: 'Happy to do a video call first! Text me at 415-555-0101' },
      { displayName: 'Pat Nguyen', bio: 'Nurse at UCSF, weird hours. Need quiet daytime. Love cooking, happy to share meals! Budget: $1800/mo.', selectsEveryone: true, contact: 'pat.nguyen@ucsf.edu', message: 'Let\'s meet for coffee and chat about the living situation!' },
      { displayName: 'Jesse Garcia', bio: 'Remote PM, into climbing and hiking. Looking for active housemates. 420 friendly. Budget: $2500/mo.', selectsEveryone: true, contact: '@jessegarciapm', message: 'IG DMs work best for me!' },
      { displayName: 'Morgan Taylor', bio: 'Grad student at Berkeley, tight budget. Bookworm, homebody. LGBTQ+ friendly required. Budget: $1500/mo.', contact: 'morgan.taylor@berkeley.edu' },
      { displayName: 'Alex Rivera', bio: 'Chef, late night schedule. Very clean kitchen! Looking for chill roommates. Budget: $2000/mo.', contact: 'alex.chef.rivera@gmail.com' },
      { displayName: 'Jamie Chen', bio: 'Freelance designer, home studio setup. Need good natural light room. Have a quiet dog. Budget: $2300/mo.', contact: '@jamiechendesign' },
      { displayName: 'Sam Kim', bio: 'Startup founder, busy schedule. Mostly just need a place to sleep. Low maintenance. Budget: $2800/mo.', contact: 'sam.kim@startup.io' },
      { displayName: 'Jordan Brooks', bio: 'Teacher, early schedule. Yoga and meditation practice. Looking for mindful, tidy housemates. Budget: $1900/mo.', contact: 'jordan.brooks.teach@gmail.com' },
      { displayName: 'Casey Lee', bio: 'Marketing manager, social but respectful. Occasional dinner parties OK? Have furniture. Budget: $2400/mo.', contact: 'casey.lee.mktg@gmail.com' },
      { displayName: 'Riley Martinez', bio: 'Musician (headphones only at home!). Night owl but quiet. Looking for creative household. Budget: $1700/mo.', contact: '@rileymartinezmusic' },
      { displayName: 'Avery Williams', bio: 'Consultant, travel 50% of time. Clean, minimal stuff. Just need chill people for when I\'m home. Budget: $2600/mo.', contact: 'avery.williams@consulting.com' },
      { displayName: 'Quinn O\'Brien', bio: 'Vet tech, animal lover. Have 2 cats, non-negotiable. Looking for pet-friendly house. Budget: $2100/mo.', contact: 'quinn.obrien.vet@gmail.com' },
    ],
  },
];

const DATA_DIR = process.env.RENDEZVOUS_DATA_DIR || './data';
const DB_PATH = path.join(DATA_DIR, 'rendezvous.db');

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const rv = createRendezvous(DB_PATH);

console.log('🌱 Seeding test data...\n');

// Pre-generate a test user keypair that participants will select
// This allows the test user to get guaranteed matches!
const testUserKeypair = generateKeypair();
console.log('🔑 Generated test user keypair (USE THIS IN THE WEB UI!)');
console.log('   Public Key:  ' + testUserKeypair.publicKey);
console.log('   Private Key: ' + testUserKeypair.privateKey);
console.log('');

interface ParticipantWithKey {
  id: string;
  poolId: string;
  publicKey: string;
  displayName: string;
  bio?: string;
  registeredAt: Date;
  privateKey: string;
  selectsEveryone?: boolean;
  contact?: string;
  message?: string;
}

interface CreatedPool {
  id: string;
  name: string;
  emoji: string;
}

const createdPools: CreatedPool[] = [];

// Create all pools
for (const poolConfig of SEED_POOLS) {
  console.log(`${poolConfig.emoji} Creating pool: ${poolConfig.name}`);
  console.log('─'.repeat(50));

  const creatorKeypair = generateKeypair();
  const signingKeypair = generateSigningKeypair();
  const pool = rv.createPool({
    name: poolConfig.name,
    description: poolConfig.description,
    creatorPublicKey: creatorKeypair.publicKey,
    creatorSigningKey: signingKeypair.signingPublicKey,
    revealDeadline: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
    maxPreferencesPerParticipant: 20,
    eligibilityGate: { type: 'open' },
    requiresInviteToJoin: true,
  });

  createdPools.push({ id: pool.id, name: pool.name, emoji: poolConfig.emoji });

  console.log('   ID: ' + pool.id);
  console.log('   Deadline: ' + pool.revealDeadline.toLocaleString());
  console.log('');

  // Register participants for this pool
  console.log('   👥 Registering participants...');

  const participants: ParticipantWithKey[] = [];

  for (const fake of poolConfig.participants) {
    const keypair = generateKeypair();
    const participant = rv.registerParticipant({
      poolId: pool.id,
      publicKey: keypair.publicKey,
      displayName: fake.displayName,
      bio: fake.bio,
    });
    participants.push({
      ...participant,
      privateKey: keypair.privateKey,
      selectsEveryone: fake.selectsEveryone,
      contact: fake.contact,
      message: fake.message,
    });
    console.log('      + ' + fake.displayName + (fake.selectsEveryone ? ' ⭐' : '') + (fake.contact ? ' 📧' : ''));
  }

  console.log('');
  console.log('   ✅ Registered ' + participants.length + ' participants');

  // Have "selectsEveryone" participants submit preferences
  console.log('   🎲 Submitting preferences...');

  for (const participant of participants) {
    if (participant.selectsEveryone) {
      // Select all OTHER participants PLUS the test user
      const otherKeys = participants
        .filter(p => p.publicKey !== participant.publicKey)
        .map(p => p.publicKey);

      // Include the test user keypair so they get guaranteed matches!
      otherKeys.push(testUserKeypair.publicKey);

      const tokens = deriveMatchTokens(participant.privateKey, otherKeys, pool.id);
      const nullifier = deriveNullifier(participant.privateKey, pool.id);

      // Create encrypted reveal data for each selection
      const revealData: { matchToken: string; encryptedReveal: string }[] = [];
      if (participant.contact || participant.message) {
        const revealContent = { contact: participant.contact || '', message: participant.message || '' };
        for (const otherKey of otherKeys) {
          const token = deriveMatchToken(participant.privateKey, otherKey, pool.id);
          const encrypted = encryptRevealData(revealContent, token);
          revealData.push({ matchToken: token, encryptedReveal: encrypted });
        }
      }

      rv.submitPreferences({
        poolId: pool.id,
        matchTokens: tokens,
        nullifier,
        revealData: revealData.length > 0 ? revealData : undefined,
      });

      console.log('      ' + participant.displayName + ' selected everyone (' + otherKeys.length + ' people)' + (revealData.length ? ' + contact info' : ''));
    }
  }

  // Add some specific selections for the first pool (social mixer) to create interesting dynamics
  if (poolConfig.name === 'Friday Night Mixer') {
    const specificSelections = [
      { from: 3, to: [0, 4] },      // Emma -> Bob, Frank
      { from: 4, to: [1, 5] },      // Frank -> Carol, Grace
      { from: 5, to: [2, 6] },      // Grace -> David, Henry
    ];

    for (const sel of specificSelections) {
      const fromParticipant = participants[sel.from];
      const toPublicKeys = sel.to.map(i => participants[i].publicKey);

      const tokens = deriveMatchTokens(fromParticipant.privateKey, toPublicKeys, pool.id);
      const nullifier = deriveNullifier(fromParticipant.privateKey, pool.id);

      // Create encrypted reveal data for each selection
      const revealData: { matchToken: string; encryptedReveal: string }[] = [];
      if (fromParticipant.contact || fromParticipant.message) {
        const revealContent = { contact: fromParticipant.contact || '', message: fromParticipant.message || '' };
        for (const toKey of toPublicKeys) {
          const token = deriveMatchToken(fromParticipant.privateKey, toKey, pool.id);
          const encrypted = encryptRevealData(revealContent, token);
          revealData.push({ matchToken: token, encryptedReveal: encrypted });
        }
      }

      rv.submitPreferences({
        poolId: pool.id,
        matchTokens: tokens,
        nullifier,
        revealData: revealData.length > 0 ? revealData : undefined,
      });

      console.log('      ' + fromParticipant.displayName + ' selected ' + sel.to.length + ' specific people' + (revealData.length ? ' + contact info' : ''));
    }
  }

  console.log('');
}

rv.close();

// Output instructions
console.log('');
console.log('═══════════════════════════════════════════════════════════════');
console.log('');
console.log('🚀 To test the Web UI:');
console.log('');
console.log('   1. Start the server: npm run server');
console.log('');
console.log('   2. Open http://localhost:3000');
console.log('');
console.log('   3. Go to "Browse & Select" tab');
console.log('      - Select any pool from the dropdown');
console.log('      - Enter the PUBLIC KEY from above');
console.log('      - Register with any name you like');
console.log('');
console.log('   4. Browse participants and select those marked with ⭐');
console.log('      (they have already selected the test user!)');
console.log('');
console.log('   5. On the confirmation screen, enter the PRIVATE KEY from above');
console.log('      - Click "Submit Encrypted Preferences"');
console.log('');
console.log('   6. Go to "Pools" tab → click pool → "Close Pool"');
console.log('');
console.log('   7. Go to "Discover Matches" tab');
console.log('      - Select the pool you participated in');
console.log('      - Enter your private key');
console.log('      - See your matches!');
console.log('');
console.log('═══════════════════════════════════════════════════════════════');
console.log('');
console.log('📋 CREATED POOLS:');
console.log('');
for (const p of createdPools) {
  console.log(`   ${p.emoji} ${p.name}`);
  console.log(`      ID: ${p.id}`);
  console.log('');
}
console.log('═══════════════════════════════════════════════════════════════');
console.log('');
console.log('💡 IMPORTANT: Use the keypair printed above!');
console.log('   Participants marked with ⭐ have already selected that public key.');
console.log('   If you generate a NEW key, they won\'t have selected you!');
console.log('');
console.log('   Test User Public Key:  ' + testUserKeypair.publicKey);
console.log('   Test User Private Key: ' + testUserKeypair.privateKey);
console.log('');
console.log('Done! 🎉');
