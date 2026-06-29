const {Ed25519KeyPair, forge, jsonld, util, Buffer, jsYaml, base58, N3Writer, N3WriterWrapper} = rdfsig;
const $ = document.querySelectorAll.bind(document);
const DefaultManifest = ['examples/toy.yaml'];
const F = graphy.core.data.factory;

const NS = {
  sec:  'https://w3id.org/security#',
  fhir: 'http://hl7.org/fhir/',
  rdf:  'http://www.w3.org/1999/02/22-rdf-syntax-ns#',
};

const RDF_TYPE = NS.rdf + 'type';

const ProofTypeInfo = {
  [NS.sec + 'Ed25519Signature2018']: { keyClass: 'Ed25519', alg: 'EdDSA' },
  [NS.sec + 'Ed25519Signature2020']: { keyClass: 'Ed25519', alg: 'EdDSA' },
  [NS.sec + 'RsaSignature2018']:     { keyClass: 'RSA',     alg: 'RS256' },
};

const SigKinds = {
  jws: {
    predicate: NS.sec + 'jws',
    create: createJwsToken,
    verify: verifyJwsToken,
  },
  proofValue: {
    predicate: NS.sec + 'proofValue',
    create: createProofValue,
    verify: verifyProofValue,
  },
};

const SearchParms = parseQueryString(window.location.search);
console.log(`Page loaded at ${new Date().toISOString()} with search parms:\n${JSON.stringify(SearchParms, null, 2)}`);

// Paint example buttons.
$('#signGraph')[0].value = ''; // clear out for error messages
(SearchParms.manifestURL || DefaultManifest).forEach(async (m) => {
  let verb = 'load';
  try {
    const resp = await fetch(m);
    if (!resp.ok)
      throw Error(`fetch ${m} returned ${resp.status} ${resp.statusText}`);
    const text = await resp.text();
    verb = 'parse';
    const manifest = m.endsWith('.yaml')
          ? jsYaml.load(text)
          : JSON.parse(text);
    Object.keys(manifest).forEach(label => {
      const elt = document.createElement('button');
      elt.innerText = label
      elt.onclick = () => fill(manifest[label]);
      $('#manifest')[0].appendChild(elt);
    })
  } catch (e) {
    $('#signGraph')[0].value += `Failed to ${verb} ${m}: ${e.message}\n`;
  }
})

const Fields = [
  '#alg',        // 0  signing inputs
  '#signNode',   // 1
  '#signGraph',  // 2
  '#proofNode',  // 3
  '#withProof',  // 4
  '#keyId',      // 5
  '#privKey',    // 6
  '#pubKey',     // 7  verification input (stable across re-signs)
  '#signed',     // 8  signing output
  '#verifyMe',   // 9  verification input
  '#result',     // 10 verification output
];
const ClearFrom = {
  fill:     Fields.indexOf('#alg'),
  sign:     Fields.indexOf('#signed'),
  copyDown: Fields.indexOf('#verifyMe'),
  verify:   Fields.indexOf('#result'),
};
function setVerifyState(state) {
  document.body.classList.remove('state-verified', 'state-failed');
  if (state) document.body.classList.add('state-' + state);
}

function clearFrom (offset) {
  Fields.slice(offset).forEach(sel => { $(sel)[0].value = ''; });
  $('#proofMeta')[0].textContent = '';
  setVerifyState(null);
}

// Example button action.
function fill (fields) {
  clearFrom(ClearFrom.fill);
  Object.keys(fields).forEach(id => {
    const el = document.querySelector('#' + id);
    if (el) el.value = fields[id];
  });
  detectAlgFromProof();
}

// ---------------------------------------------------------------------------
// Linked-data proof helpers (jws / proofValue)
// ---------------------------------------------------------------------------

// Detect key class and JWS algorithm from proof rdf:type triple.
function getProofTypeInfo (dataset, proofNode) {
  const typeQuads = [...dataset.match(proofNode, F.namedNode(RDF_TYPE), null)];
  if (typeQuads.length === 0)
    throw Error('No rdf:type found for proof node');
  const proofType = typeQuads[0].object.value;
  const info = ProofTypeInfo[proofType];
  if (!info)
    throw Error(`Unknown proof type: ${proofType}`);
  return { proofType, ...info };
}

// Build an RS256 (RSASSA-PKCS1-v1_5 + SHA-256) signer from base58 PKCS#1 DER.
function makeRsaSigner (privKeyBase58) {
  const privKey = forge.pki.privateKeyFromAsn1(
    forge.asn1.fromDer(forge.util.createBuffer(base58.decode(privKeyBase58))));
  return {
    sign: async ({data}) => {
      const md = forge.md.sha256.create();
      md.update(forge.util.binary.raw.encode(data), 'binary');
      return forge.util.binary.raw.decode(privKey.sign(md));
    }
  };
}

// Build an RS256 verifier from base58 SubjectPublicKeyInfo DER.
function makeRsaVerifier (pubKeyBase58) {
  const pubKey = forge.pki.publicKeyFromAsn1(
    forge.asn1.fromDer(forge.util.createBuffer(base58.decode(pubKeyBase58))));
  return {
    verify: async ({data, signature}) => {
      const md = forge.md.sha256.create();
      md.update(forge.util.binary.raw.encode(data), 'binary');
      try {
        return pubKey.verify(md.digest().bytes(), forge.util.binary.raw.encode(signature));
      } catch (e) { return false; }
    }
  };
}

// ---------------------------------------------------------------------------
// FHIR helpers
// ---------------------------------------------------------------------------

// BFS extract of all triples reachable from rootNode through blank-node objects.
// Deletes extracted triples from dataset and returns them.
function extractSubgraph (dataset, rootNode) {
  const quads = [];
  const queue = [rootNode];
  const visited = new Set();
  while (queue.length > 0) {
    const node = queue.shift();
    const key = node.termType + ':' + node.value;
    if (visited.has(key)) continue;
    visited.add(key);
    for (const q of dataset.match(node, null, null)) {
      quads.push(q);
      if (q.object.termType === 'BlankNode')
        queue.push(q.object);
    }
  }
  quads.forEach(q => dataset.delete(q));
  return quads;
}

// Walk resourceNode → fhir:signature → fhir:data → fhir:v and return the literal value.
function findFhirSigToken (dataset, resourceNode) {
  const sigQ = [...dataset.match(resourceNode, F.namedNode(NS.fhir + 'signature'), null)];
  if (!sigQ.length) throw Error(`No fhir:signature on ${resourceNode.value}`);
  const sigBN = sigQ[0].object;
  const dataQ = [...dataset.match(sigBN, F.namedNode(NS.fhir + 'data'), null)];
  if (!dataQ.length) throw Error('No fhir:data on fhir:signature node');
  const dataBN = dataQ[0].object;
  const vQ = [...dataset.match(dataBN, F.namedNode(NS.fhir + 'v'), null)];
  if (!vQ.length) throw Error('No fhir:v on fhir:data node');
  return { sigBN, token: vQ[0].object.value };
}

// Rename all blank nodes in a dataset using a string prefix (returns new dataset).
function renameBlankNodes (dataset, prefix) {
  const out = graphy.memory.dataset.fast();
  for (const q of dataset.quads()) {
    const s = q.subject.termType === 'BlankNode' ? F.blankNode(prefix + q.subject.value) : q.subject;
    const o = q.object.termType === 'BlankNode' ? F.blankNode(prefix + q.object.value) : q.object;
    out.add(F.quad(s, q.predicate, o, q.graph));
  }
  return out;
}

// ---------------------------------------------------------------------------
// Signature metadata extraction
// ---------------------------------------------------------------------------

function fhirVal(ds, subj, predIRI) {
  for (const q1 of ds.match(subj, F.namedNode(predIRI), null))
    for (const q2 of ds.match(q1.object, F.namedNode(NS.fhir + 'v'), null))
      return q2.object.value;
  return null;
}
function fhirRef(ds, subj, predIRI) {
  for (const q1 of ds.match(subj, F.namedNode(predIRI), null))
    for (const q2 of ds.match(q1.object, F.namedNode(NS.fhir + 'reference'), null))
      for (const q3 of ds.match(q2.object, F.namedNode(NS.fhir + 'v'), null))
        return q3.object.value;
  return null;
}
function rdfListFirst(ds, listHead) {
  for (const q of ds.match(listHead, F.namedNode(NS.rdf + 'first'), null))
    return q.object;
  return null;
}
function extractSignMeta(sigKind, ds, rootNode) {
  const meta = {};
  const DC_CREATED = 'http://purl.org/dc/terms/created';
  if (sigKind === 'jws' || sigKind === 'proofValue') {
    for (const q of ds.match(rootNode, F.namedNode(RDF_TYPE), null))
      meta.type = q.object.value.replace(NS.sec, 'sec:');
    for (const q of ds.match(rootNode, F.namedNode(DC_CREATED), null))
      meta.created = q.object.value;
    for (const q of ds.match(rootNode, F.namedNode(NS.sec + 'proofPurpose'), null))
      meta.proofPurpose = q.object.value.replace(NS.sec, 'sec:');
    for (const q of ds.match(rootNode, F.namedNode(NS.sec + 'verificationMethod'), null))
      meta.verificationMethod = q.object.value;
  } else if (sigKind === 'fhirBundle') {
    for (const q of ds.match(rootNode, F.namedNode(NS.fhir + 'signature'), null)) {
      const sig = q.object;
      meta.when         = fhirVal(ds, sig, NS.fhir + 'when');
      meta.who          = fhirRef(ds, sig, NS.fhir + 'who');
      meta.sigFormat    = fhirVal(ds, sig, NS.fhir + 'sigFormat');
      meta.targetFormat = fhirVal(ds, sig, NS.fhir + 'targetFormat');
      for (const qt of ds.match(sig, F.namedNode(NS.fhir + 'type'), null))
        for (const qc of ds.match(qt.object, F.namedNode(NS.fhir + 'coding'), null)) {
          const coding = rdfListFirst(ds, qc.object);
          if (coding) {
            meta.code       = fhirVal(ds, coding, NS.fhir + 'code');
            meta.codeSystem = fhirVal(ds, coding, NS.fhir + 'system');
          }
        }
    }
  } else { // fhirProvenance
    meta.recorded = fhirVal(ds, rootNode, NS.fhir + 'recorded');
    for (const qa of ds.match(rootNode, F.namedNode(NS.fhir + 'agent'), null)) {
      meta.who = fhirRef(ds, qa.object, NS.fhir + 'who');
      for (const qt of ds.match(qa.object, F.namedNode(NS.fhir + 'type'), null))
        for (const qc of ds.match(qt.object, F.namedNode(NS.fhir + 'coding'), null)) {
          const coding = rdfListFirst(ds, qc.object);
          if (coding) {
            meta.participantType = fhirVal(ds, coding, NS.fhir + 'code');
            meta.codeSystem      = fhirVal(ds, coding, NS.fhir + 'system');
          }
        }
    }
    for (const qs of ds.match(rootNode, F.namedNode(NS.fhir + 'signature'), null)) {
      meta.when      = fhirVal(ds, qs.object, NS.fhir + 'when');
      meta.sigFormat = fhirVal(ds, qs.object, NS.fhir + 'sigFormat');
    }
  }
  return Object.fromEntries(Object.entries(meta).filter(([, v]) => v != null));
}
function showProofMeta(meta) {
  $('#proofMeta')[0].textContent = Object.entries(meta).map(([k, v]) => `${k}: ${v}`).join('\n');
}

async function signFhir (vals) {
  const signGraph = await parse('ttl', vals.signGraph);
  const withProof = await parse('ttl', vals.withProof);
  const proofNode = parseNode(vals.proofNode);
  const alg = vals.alg || 'RS256';

  // Only signGraph is signed — withProof (Provenance metadata or sig metadata) is not.
  const signer = makeRsaSigner(vals.privKey);
  const verifyData = await urdnaizeDocs([
    await write('nt', [...signGraph.data.quads()]),
  ]);

  const token = await createJwsToken(verifyData, signer, alg);

  // Inject fhir:data [ fhir:v token ] into withProof before renaming.
  const sigQ = [...withProof.data.match(proofNode, F.namedNode(NS.fhir + 'signature'), null)];
  if (!sigQ.length) throw Error(`No fhir:signature on ${proofNode.value}`);
  const sigBN = sigQ[0].object;
  const dataBN = F.blankNode();
  withProof.data.add(F.quad(sigBN, F.namedNode(NS.fhir + 'data'), dataBN));
  withProof.data.add(F.quad(dataBN, F.namedNode(NS.fhir + 'v'), F.literal(token)));

  // Rename withProof blank nodes with 'wp' prefix to prevent collision with
  // signGraph blank nodes (graphy assigns sequential labels g0,g1,... per parse call).
  const withProofRenamed = renameBlankNodes(withProof.data, 'wp');
  signGraph.data.addAll(withProofRenamed.quads());

  // For co-signed Bundles: append the Provenance as the last element of the
  // Bundle's fhir:entry RDF collection (first/rest list), matching the FHIR RDF
  // serialization used for the other entries.
  if (vals.sigKind === 'fhirProvenance') {
    const signNodeIRI = parseNode(vals.signNode);
    const rdfFirst = F.namedNode(NS.rdf + 'first');
    const rdfRest  = F.namedNode(NS.rdf + 'rest');
    const rdfNil   = F.namedNode(NS.rdf + 'nil');
    const entryBN       = F.blankNode('wpEntry');
    const fullUrlBN     = F.blankNode('wpEntryFullUrl');
    const resourceListBN = F.blankNode('wpEntryResource');
    const listNodeBN    = F.blankNode('wpEntryList');
    signGraph.data.add(F.quad(entryBN, F.namedNode(NS.fhir + 'fullUrl'), fullUrlBN));
    signGraph.data.add(F.quad(fullUrlBN, F.namedNode(NS.fhir + 'v'), F.literal(proofNode.value, F.namedNode('http://www.w3.org/2001/XMLSchema#anyURI'))));
    signGraph.data.add(F.quad(fullUrlBN, F.namedNode(NS.fhir + 'l'), proofNode));
    signGraph.data.add(F.quad(entryBN, F.namedNode(NS.fhir + 'resource'), resourceListBN));
    signGraph.data.add(F.quad(resourceListBN, rdfFirst, proofNode));
    signGraph.data.add(F.quad(resourceListBN, rdfRest, rdfNil));
    signGraph.data.add(F.quad(listNodeBN, rdfFirst, entryBN));
    signGraph.data.add(F.quad(listNodeBN, rdfRest, rdfNil));
    const entryHeads = [...signGraph.data.match(signNodeIRI, F.namedNode(NS.fhir + 'entry'), null)];
    if (entryHeads.length > 0) {
      let cur = entryHeads[0].object;
      while (true) {
        const rest = [...signGraph.data.match(cur, rdfRest, null)];
        if (!rest.length || rest[0].object.equals(rdfNil)) {
          if (rest.length) signGraph.data.delete(rest[0]);
          signGraph.data.add(F.quad(cur, rdfRest, listNodeBN));
          break;
        }
        cur = rest[0].object;
      }
    } else {
      signGraph.data.add(F.quad(signNodeIRI, F.namedNode(NS.fhir + 'entry'), listNodeBN));
    }
  }

  const text = await write('ttl', [...signGraph.data], {
    prefixes: Object.assign({
      fhir: NS.fhir,
      xsd: 'http://www.w3.org/2001/XMLSchema#',
    }, signGraph.prefixes, withProof.prefixes)
  });
  $('#signed')[0].value = text;
  $('#detectedAlg')[0].textContent = `${vals.sigKind} → alg: ${alg}`;
}

async function verifyFhir (vals) {
  const verifyGraph = await parse('ttl', vals.verifyMe);
  const signNode = parseNode(vals.signNode);
  const alg = vals.alg || 'RS256';

  let token, meta;

  if (vals.sigKind === 'fhirBundle') {
    // Extract token and strip fhir:signature subgraph from Bundle.
    const sigQ = [...verifyGraph.data.match(signNode, F.namedNode(NS.fhir + 'signature'), null)];
    if (!sigQ.length) throw Error('No fhir:signature found on Bundle');
    const sigBN = sigQ[0].object;
    meta = extractSignMeta('fhirBundle', verifyGraph.data, signNode);
    token = findFhirSigToken(verifyGraph.data, signNode).token;
    verifyGraph.data.delete(sigQ[0]);         // remove signNode→fhir:signature triple; deteches signature from the graph
    extractSubgraph(verifyGraph.data, sigBN); // remove signature subgraph

  } else { // fhirProvenance
    // Find a Provenance whose fhir:target fhir:reference fhir:v matches the Bundle.
    // The reference is stored as a relative URL like "Bundle/signed".
    const bundleRef = signNode.value.replace(/^https?:\/\/[^/]+\/fhir\//, '');
    let provNode = null;
    outer: for (const q1 of verifyGraph.data.match(null, F.namedNode(NS.fhir + 'target'), null)) {
      for (const q2 of verifyGraph.data.match(q1.object, F.namedNode(NS.fhir + 'reference'), null)) {
        for (const q3 of verifyGraph.data.match(q2.object, F.namedNode(NS.fhir + 'v'), null)) {
          if (q3.object.value === bundleRef || q3.object.value === signNode.value) {
            provNode = q1.subject;
            break outer;
          }
        }
      }
    }
    if (!provNode) throw Error(`No co-signing Provenance found targeting ${signNode.value}`);
    meta = extractSignMeta('fhirProvenance', verifyGraph.data, provNode);
    token = findFhirSigToken(verifyGraph.data, provNode).token;
    // Walk the fhir:entry RDF collection on signNode to find and splice out the
    // Provenance list node, restoring the original signed Bundle structure.
    const rdfFirst = F.namedNode(NS.rdf + 'first');
    const rdfRest  = F.namedNode(NS.rdf + 'rest');
    const rdfNil   = F.namedNode(NS.rdf + 'nil');
    const entryHeads = [...verifyGraph.data.match(signNode, F.namedNode(NS.fhir + 'entry'), null)];
    if (entryHeads.length > 0) {
      let prev = null;
      let cur = entryHeads[0].object;
      let found = false;
      while (!found && !cur.equals(rdfNil)) {
        const firstQs = [...verifyGraph.data.match(cur, rdfFirst, null)];
        const restQs  = [...verifyGraph.data.match(cur, rdfRest,  null)];
        const next = restQs.length ? restQs[0].object : rdfNil;
        if (firstQs.length > 0 && firstQs[0].object.termType === 'BlankNode') {
          const entryBN = firstQs[0].object;
          for (const rq of verifyGraph.data.match(entryBN, F.namedNode(NS.fhir + 'resource'), null)) {
            if (rq.object.termType !== 'BlankNode') continue;
            const rfQs = [...verifyGraph.data.match(rq.object, rdfFirst, null)];
            if (rfQs.length > 0 && rfQs[0].object.equals(provNode)) {
              if (prev) {
                const prevRest = [...verifyGraph.data.match(prev, rdfRest, null)];
                if (prevRest.length) verifyGraph.data.delete(prevRest[0]);
                verifyGraph.data.add(F.quad(prev, rdfRest, next));
              } else {
                verifyGraph.data.delete(entryHeads[0]);
                if (!next.equals(rdfNil))
                  verifyGraph.data.add(F.quad(signNode, F.namedNode(NS.fhir + 'entry'), next));
              }
              extractSubgraph(verifyGraph.data, cur); // removes list node + entry BN + fullUrl + resource list
              found = true;
              break;
            }
          }
        }
        if (!found) { prev = cur; cur = next; }
      }
    }
    extractSubgraph(verifyGraph.data, provNode); // strip Provenance and all its blank nodes
  }

  const verifier = makeRsaVerifier(vals.pubKey);
  const verifyData = await urdnaizeDocs([
    await write('nt', [...verifyGraph.data.quads()]),
  ]);
  const verified = await verifyJwsToken(token, verifyData, verifier);
  $('#result')[0].value = verified;
  $('#detectedAlg')[0].textContent = `${vals.sigKind} → alg: ${alg}`;
  return meta;
}

// ---------------------------------------------------------------------------
// Sign button
// ---------------------------------------------------------------------------
$('#sign')[0].onclick = async function (evt) {
  debugger; // so folks can follow along
  clearFrom(ClearFrom.sign);
  try {
    const vals = (['sigKind', 'signGraph', 'signNode', 'withProof', 'proofNode', 'privKey', 'alg']).reduce((acc, key) => {
      acc[key] = $('#' + key)[0].value;
      return acc;
    }, {});

    if (vals.sigKind === 'fhirProvenance' || vals.sigKind === 'fhirBundle') {
      await signFhir(vals);
      return;
    }

    const [signGraph, withProof] = await Promise.all([
      parse('ttl', vals.signGraph),
      parse('ttl', vals.withProof),
    ]);
    const signNode = parseNode(vals.signNode);
    const proofNode = parseNode(vals.proofNode);

    // Detect key class and JWS algorithm from proof type.
    const { proofType, keyClass, alg } = getProofTypeInfo(withProof.data, proofNode);
    $('#detectedAlg')[0].textContent =
      `detected: ${proofType.replace(NS.sec, 'sec:')} → alg: ${alg}`;

    // Copy embedded proof with BlankNode subject.
    const embeddedProofNode = F.blankNode();
    const anonymousProof = graphy.memory.dataset.fast();
    ([...withProof.data.quads(null, null, null, null)]).map(q => {
      if (q.subject.equals(proofNode))
        q.subject = embeddedProofNode;
      if (q.object.equals(proofNode))
        q.object = embeddedProofNode;
      anonymousProof.add(q);
    });

    // Construct signing key.
    let signer;
    if (keyClass === 'Ed25519') {
      const keyPair = await Ed25519KeyPair.generate({ privateKeyBase58: vals.privKey });
      signer = keyPair.signer();
    } else if (keyClass === 'RSA') {
      signer = makeRsaSigner(vals.privKey);
    } else {
      throw Error(`Unsupported key class: ${keyClass}`);
    }

    // Compose signature applies to concatenation of both graphs.
    const verifyData = await urdnaizeDocs([
      await write('nt', [...anonymousProof.quads()]),
      await write('nt', [...signGraph.data.quads()]),
    ]);

    // Add signed scalar to proof.
    anonymousProof.add(F.quad(
      embeddedProofNode,
      F.namedNode(SigKinds[sigKind.value].predicate),
      F.literal(await SigKinds[sigKind.value].create(verifyData, signer, alg))
    ));

    // Connect proof to signed node.
    signGraph.data.add(F.quad(
      signNode,
      F.namedNode(NS.sec + 'proof'),
      embeddedProofNode
    ));

    // Write composite graph to UI.
    signGraph.data.addAll(anonymousProof.quads());
    const text = await write('ttl', [...signGraph.data], {
      prefixes: Object.assign({}, {
        cred: 'https://www.w3.org/2018/credentials#',
        rdf: NS.rdf,
      }, signGraph.prefixes, withProof.prefixes)
    });
    $('#signed')[0].value = text;
  } catch (e) {
    $('#signed')[0].value = 'Error: ' + (typeof e === 'object' ? 'message' in e ? e.message : JSON.stringify(e) : e)
  }
}

$('#copyDown')[0].onclick = function (evt) {
  clearFrom(ClearFrom.copyDown);
  $('#verifyMe')[0].value = $('#signed')[0].value;
}

// ---------------------------------------------------------------------------
// Verify button
// ---------------------------------------------------------------------------
$('#verify')[0].onclick = async function (evt) {
  debugger; // so folks can follow along
  clearFrom(ClearFrom.verify);
  try {
    const vals = (['sigKind', 'verifyMe', 'pubKey', 'keyId', 'signNode', 'alg']).reduce((acc, key) => {
      acc[key] = $('#' + key)[0].value;
      return acc;
    }, {});

    if (vals.sigKind === 'fhirProvenance' || vals.sigKind === 'fhirBundle') {
      showProofMeta(await verifyFhir(vals));
    } else {

    const verifyGraph = await parse('ttl', vals.verifyMe);

    // Find the quad with predicate sec:proof
    const proofQuad = extract(
      1, {subject: undefined, object: 'BlankNode'},
      'asserted proof',
      verifyGraph.data,
      null,
      F.namedNode(NS.sec + 'proof'),
      null
    )[0];
    const signNode = proofQuad.subject;
    const embeddedProofNode = proofQuad.object;

    // Find the signature token.
    const signature = extract(
      1, {subject: 'BlankNode', object: 'Literal'},
      sigKind.value,
      verifyGraph.data,
      embeddedProofNode,
      F.namedNode(SigKinds[sigKind.value].predicate),
      null
    )[0].object.value;

    // Extract the proof graph.
    const anonymousProof = graphy.memory.dataset.fast();
    anonymousProof.addAll(extract(
      null, {},
      'proof triples',
      verifyGraph.data,
      embeddedProofNode,
      null,
      null
    ));

    // Detect key class and algorithm from proof type.
    const { proofType, keyClass, alg } = getProofTypeInfo(anonymousProof, embeddedProofNode);
    $('#detectedAlg')[0].textContent =
      `detected: ${proofType.replace(NS.sec, 'sec:')} → alg: ${alg}`;
    const meta = extractSignMeta(vals.sigKind, anonymousProof, embeddedProofNode);

    // Construct public key verifier.
    let verifier;
    if (keyClass === 'Ed25519') {
      const keyPair = await Ed25519KeyPair.generate({
        id: vals.keyId,
        publicKeyBase58: vals.pubKey,
      });
      verifier = keyPair.verifier();
    } else if (keyClass === 'RSA') {
      verifier = makeRsaVerifier(vals.pubKey);
    } else {
      throw Error(`Unsupported key class: ${keyClass}`);
    }

    // Verify that signature applies to concatenation of both graphs.
    const verifyData = await urdnaizeDocs([
      await write('nt', [...anonymousProof.quads()]),
      await write('nt', [...verifyGraph.data.quads()]),
    ]);
    const verified = await SigKinds[sigKind.value].verify(signature, verifyData, verifier);
    $('#result')[0].value = verified;
    showProofMeta(meta);
    } // else jws/proofValue
  } catch (e) {
    $('#result')[0].value = e.message;
  }
  setVerifyState($('#result')[0].value === 'true' ? 'verified' : 'failed');
}

// ---------------------------------------------------------------------------
// Key bindings  C-Enter=sign  C-↓=copyDown  C-\=verify
// ---------------------------------------------------------------------------
$('#verifyMe')[0].addEventListener('input', () => setVerifyState(null));

// Eagerly detect and display the algorithm from the withProof type triple.
async function detectAlgFromProof() {
  const sigKindVal = $('#sigKind')[0].value;
  if (sigKindVal === 'fhirProvenance' || sigKindVal === 'fhirBundle') {
    $('#detectedAlg')[0].textContent = '';
    return;
  }
  const proofText = $('#withProof')[0].value.trim();
  const proofNodeText = $('#proofNode')[0].value.trim();
  if (!proofText || !proofNodeText) {
    $('#detectedAlg')[0].textContent = '';
    return;
  }
  try {
    const withProof = await parse('ttl', proofText);
    const proofNode = parseNode(proofNodeText);
    const { proofType, alg } = getProofTypeInfo(withProof.data, proofNode);
    $('#detectedAlg')[0].textContent =
      `detected: ${proofType.replace(NS.sec, 'sec:')} → alg: ${alg}`;
  } catch (_) {
    $('#detectedAlg')[0].textContent = '';
  }
}
['#withProof', '#proofNode', '#sigKind'].forEach(sel =>
  $(sel)[0].addEventListener('input', detectAlgFromProof));

// ---------------------------------------------------------------------------
// Theme toggle
// ---------------------------------------------------------------------------
(function () {
  const btn = $('#themeToggle')[0];
  function applyTheme(dark) {
    if (dark) {
      document.documentElement.setAttribute('data-theme', 'dark');
      btn.textContent = '☀';
    } else {
      document.documentElement.removeAttribute('data-theme');
      btn.textContent = '🌙';
    }
    localStorage.setItem('theme', dark ? 'dark' : 'light');
  }
  applyTheme(document.documentElement.getAttribute('data-theme') === 'dark');
  btn.addEventListener('click', () =>
    applyTheme(document.documentElement.getAttribute('data-theme') !== 'dark'));
})();

document.addEventListener('keydown', function (evt) {
  if (!evt.ctrlKey) return;
  if (evt.key === 'Enter')     { evt.preventDefault(); $('#sign')[0].click(); }
  if (evt.key === 'ArrowDown') { evt.preventDefault(); $('#copyDown')[0].click(); }
  if (evt.key === '\\')        { evt.preventDefault(); $('#verify')[0].click(); }
});

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/** extract matching triples from a graph.
 * @param count: number | null - how many to expect
 * @param types: object - mapping of triple component to expected type
 * @param label: string - string to embed in throw Errors.
 * @param graph: Dataset (modified) - where to match s, p, o
 * @param s, p, o: Term | null - what to match
 * @returns extracted triples.
 */
function extract (count, types, label, graph, s, p, o) {
  const quads = [...graph.match(s, p, o)];
  if (count !== null && quads.length !== count)
    throw Error(`fail: expected ${count} ${label}; got ${quads.length}`);
  Object.keys(types).forEach(pos => {
    const misTyped = types[pos] ? quads.find(q => q[pos].termType !== types[pos]) : null;
    if (misTyped)
      throw Error(`fail: expected ${label} of type ${types[pos]}; got ${misTyped[pos].termType}`);
  });
  quads.forEach(q => graph.delete(q));
  return quads
}

function parseNode (lexical) {
  return lexical.startsWith('_:')
    ? F.blankNode(lexical.substr(2))
    : F.namedNode(lexical);
}

async function write (format, data, opts) {
  if (format === 'ttl') {
    const prefixes = opts?.prefixes || {};
    const writer = new N3Writer({ format: 'Turtle', prefixes });
    N3WriterWrapper.topoWrite(writer, data);
    const text = await new Promise((resolve, reject) => {
      writer.end((err, result) => err ? reject(err) : resolve(result));
    });
    return N3WriterWrapper.expandLiterals(N3WriterWrapper.reindent(text));
  }
  // 'nt' and others: use graphy
  const writer = graphy.content[format].write(opts);
  return new Promise((resolve, reject) => {
    let ret = '';
    writer.on('data', (chunk) => { ret += chunk; });
    writer.on('error', reject);
    data.forEach(q => writer.write(q));
    setTimeout(() => resolve(ret), 100);
  });
}

async function parse (format, str) {
  const data = graphy.memory.dataset.fast();
  return new Promise((resolve, reject) => {
    graphy.content[format].read(str, {
      data(y_quad) {
        data.add(y_quad);
      },
      error(error) {
        reject(error);
      },
      eof(prefixes) {
        resolve({data, prefixes});
      },
    });
  });
}

async function createJwsToken (verifyData, signer, alg = 'EdDSA') {
  const header = { alg, b64: false, crit: ['b64'] };
  const encodedHeader = util.encodeBase64Url(JSON.stringify(header));
  const data = util.createJws({encodedHeader, verifyData});
  const signature = await signer.sign({data});
  const encodedSignature = util.encodeBase64Url(signature);
  return encodedHeader + '..' + encodedSignature;
}

async function verifyJwsToken (jws, verifyData, verifier) {
  const [encodedHeader, /*payload*/, encodedSignature] = jws.split('.');
  const header = JSON.parse(util.decodeBase64UrlToString(encodedHeader));
  const signature = util.decodeBase64Url(encodedSignature);
  const data = util.createJws({encodedHeader, verifyData});
  return await verifier.verify({data: data, signature: signature});
}

async function createProofValue (verifyData, signer) {
  const signatureBytes = await signer.sign({data: verifyData});
  return proofValue = `z${base58.encode(signatureBytes)}`;
}

async function verifyProofValue (proofValue, verifyData, verifier) {
  const signatureBytes = base58.decode(proofValue.substr(1));
  return await verifier.verify({data: verifyData, signature: signatureBytes})
}

async function urdnaizeDocs (docs) {
  const canons = await Promise.all(docs.map(
    doc => jsonld.canonize(doc, {
      inputFormat: 'application/n-quads',
      algorithm: 'URDNA2015',
      format: 'application/n-quads',
      skipExpansion: false,
    })
  ));
  const bufs = canons.map(c => util.sha256(c));
  const concat = Buffer.concat(bufs.map(
    b => Buffer.from(b.buffer, b.byteOffset, b.length)
  ));
  return new Uint8Array(concat.buffer, concat.byteOffset, concat.length);
}

function parseQueryString (query) {
  if (query[0]==='?') query=query.substr(1); // optional leading '?'
  const map   = {};
  query.replace(/([^&,=]+)=?([^&,]*)(?:[&,]+|$)/g, function(match, key, value) {
    key=decodeURIComponent(key);value=decodeURIComponent(value);
    (map[key] = map[key] || []).push(value);
  });
  return map;
};
