// Explainable title similarity (0..1) for duplicate suggestions; no AI service needed.
// score = max(word overlap without filler words (Jaccard), letter-triple overlap (Dice))
// Word overlap catches reordered words; letter triples catch small spelling differences.
const STOP = new Set(['a', 'an', 'the', 'to', 'for', 'of', 'in', 'on', 'and', 'or', 'with', 'please', 'add', 'support', 'feature', 'be', 'is', 'it', 'my', 'we', 'i']);

const words = (t) => t.toLowerCase().replace(/[^a-z0-9\s]/g, ' ').split(/\s+/).filter((w) => w && !STOP.has(w));

function trigrams(t) {
  const s = ` ${t.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim()} `;
  const out = new Set();
  for (let i = 0; i < s.length - 2; i += 1) out.add(s.slice(i, i + 3));
  return out;
}

function titleSimilarity(a, b) {
  const wa = new Set(words(a));
  const wb = new Set(words(b));
  const union = new Set([...wa, ...wb]).size;
  const jaccard = union ? [...wa].filter((w) => wb.has(w)).length / union : 0;
  const ta = trigrams(a);
  const tb = trigrams(b);
  const dice = ta.size + tb.size ? (2 * [...ta].filter((g) => tb.has(g)).length) / (ta.size + tb.size) : 0;
  return Math.round(Math.max(jaccard, dice) * 100) / 100;
}

module.exports = { titleSimilarity };
