import fs from 'fs';
import { fileURLToPath } from 'url';
import { runClientMockAnalysis } from './src/services/mockAnalyzer.js';

// Same cases the Python backend is tested against (backend/tests/test_parity.py)
const casesPath = fileURLToPath(new URL('../backend/tests/parity_cases.json', import.meta.url));
const { cases } = JSON.parse(fs.readFileSync(casesPath, 'utf-8'));

console.log(`Checking offline simulation parity on ${cases.length} shared cases:`);

let failures = 0;
for (const c of cases) {
  const result = runClientMockAnalysis(c.url);
  const ruleIds = result.findings.map(f => f.rule_id);
  const ok =
    JSON.stringify(ruleIds) === JSON.stringify(c.expected_rule_ids) &&
    result.risk_score === c.expected_score;

  if (ok) {
    console.log(`✅ ${c.name} -> ${result.risk_score}`);
  } else {
    failures++;
    console.error(`❌ ${c.name}`);
    console.error(`   expected ${c.expected_score} ${JSON.stringify(c.expected_rule_ids)}`);
    console.error(`   got      ${result.risk_score} ${JSON.stringify(ruleIds)}`);
  }
}

if (failures) {
  console.error(`\n${failures} case(s) differ from the Python backend.`);
  process.exit(1);
}
console.log('\nOffline simulation matches the Python backend on every case.');
