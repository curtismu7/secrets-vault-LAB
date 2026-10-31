// Writes server/src/mockTable.json from the live engine, so the Mock tables cannot drift from it (a doctor check and a test check this too).
import fs from 'node:fs';
import { installNetguard } from '../server/src/netguard.js';
import { buildMockTable } from '../server/src/scenarios.js';

installNetguard();
fs.writeFileSync(new URL('../server/src/mockTable.json', import.meta.url), `${JSON.stringify(buildMockTable())}\n`);
console.log('wrote server/src/mockTable.json');
