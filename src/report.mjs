/**
 * Report builders. buildReportModel produces the shared, plain-English report
 * content; toText keeps the original .txt export; toPdf renders a clean PDF
 * fully locally in the browser via jsPDF (no network call).
 * Long payloads are truncated in reports and nothing is ever called "safe".
 */
const MAX_REPORT_INPUT=2000;
const DISCLAIMER='QRShield is an educational cybersecurity prototype. A heuristic score is not a guarantee. Absence of warnings does NOT prove a link or payee is safe. Verify payments and links independently before acting.';

export function buildReportModel(input,analysis,live=null){
  const a=analysis||{};
  const rawInput=String(input??'');
  return {
    title:'QRShield Security Assessment',
    generatedAt:a.checkedAt||new Date().toISOString(),
    category:a.type||'unknown',
    riskLevel:String(a.level||'unknown').toUpperCase(),
    heuristicScore:a.score===null||a.score===undefined?'N/A':a.score+' / 100',
    scannedContent:rawInput.length>MAX_REPORT_INPUT?rawInput.slice(0,MAX_REPORT_INPUT)+'… [truncated, '+(rawInput.length-MAX_REPORT_INPUT)+' more characters]':rawInput,
    contentNote:rawInput.length>MAX_REPORT_INPUT?'The scanned content was shortened in this report for safety.':'',
    liveCheck:live&&live.status==='flagged'
      ?'Listed as dangerous by '+(live.source||'the threat list')+': '+live.threats.join(', ')
      :live&&live.status==='no-match'
        ?'Not found on the checked threat list ('+(live.source||'threat list')+'). This still does not prove the link is safe.'
        :'Not checked (unavailable, not configured, or not applicable).',
    headline:a.headline||'',
    summary:a.details||'',
    findings:(a.findings||[]).map(f=>({label:String(f.label||''),level:String(f.level||'unknown')})),
    recommendations:recommendationsFor(a,live),
    limitations:DISCLAIMER
  };
}

function recommendationsFor(a,live){
  const recs=[];
  if(live&&live.status==='flagged')recs.push('Do not open this link. It appears on a live threat list. Delete the message that carried it.');
  if(a.type==='upi')recs.push('Verify the payee UPI ID and amount inside your trusted payment app before paying. A QR code cannot confirm the recipient.');
  if(a.type==='url'){
    recs.push('Do not enter passwords, OTPs or card details unless you independently confirmed the site.');
    if(a.level==='high')recs.push('Avoid opening this link; multiple high-risk indicators were found.');
    else recs.push('Open links only when you trust the sender, and type important addresses yourself.');
  }
  if(a.type==='wifi')recs.push('Connect only to networks you recognise; a QR code can silently add a malicious network.');
  if(a.type==='unsafe-scheme')recs.push('Do not open or execute this payload.');
  if(!recs.length)recs.push('Stay cautious: no warning from these checks is not proof of safety.');
  return recs;
}

export function toText(model){
  const lines=[
    'QRSHIELD SECURITY ASSESSMENT',
    'Date: '+model.generatedAt,
    'Category: '+model.category,
    'Risk level: '+model.riskLevel,
    'Heuristic score: '+model.heuristicScore,
    'Live threat-list check: '+model.liveCheck,
    '',
    'Scanned content: '+model.scannedContent,
    model.contentNote,
    'Summary: '+model.headline,
    model.summary,
    '',
    'Findings:',
    ...model.findings.map(f=>'- ['+f.level.toUpperCase()+'] '+f.label),
    '',
    'Recommendations:',
    ...model.recommendations.map(r=>'- '+r),
    '',
    'LIMITATIONS: '+model.limitations
  ].filter(l=>l!==undefined&&l!==null);
  return lines.join('\n');
}

/** Render the model to a jsPDF document. jsPDF is imported by the caller bundle. */
export function toPdf(model,JsPDF){
  const doc=new JsPDF({unit:'pt',format:'a4'});
  const pageW=doc.internal.pageSize.getWidth();
  const margin=48;let y=64;
  const line=(text,size=10,style='normal',color=[31,41,55])=>{
    doc.setFont('helvetica',style);doc.setFontSize(size);doc.setTextColor(...color);
    const wrapped=doc.splitTextToSize(text,pageW-margin*2);
    for(const w of wrapped){if(y>780){doc.addPage();y=64}doc.text(w,margin,y);y+=size+5}
  };
  const gap=(n=8)=>{y+=n};
  line('QRSHIELD',22,'bold',[8,47,73]);
  line('Security Assessment Report',13,'normal',[20,83,107]);gap(14);
  doc.setDrawColor(20,83,107);doc.line(margin,y,pageW-margin,y);gap(14);
  line('Generated: '+model.generatedAt,10);
  line('Category: '+model.category+'    Risk level: '+model.riskLevel+'    Heuristic score: '+model.heuristicScore,10,'bold');
  gap(6);line('Live threat-list check: '+model.liveCheck,10);gap(10);
  line('Scanned content',11,'bold',[20,83,107]);
  line(model.scannedContent||'(empty)',9);
  if(model.contentNote)line(model.contentNote,9,'italic',[146,64,14]);
  gap(10);
  line('Summary',11,'bold',[20,83,107]);
  line(model.headline,10,'bold');line(model.summary,10);gap(10);
  line('Detection findings',11,'bold',[20,83,107]);
  if(!model.findings.length)line('No findings recorded.',10);
  for(const f of model.findings){
    const c=f.level==='high'?[185,28,28]:f.level==='caution'?[146,64,14]:[4,120,87];
    line('['+f.level.toUpperCase()+'] '+f.label,10,'normal',c);
  }
  gap(10);
  line('Security recommendations',11,'bold',[20,83,107]);
  for(const r of model.recommendations)line('• '+r,10);
  gap(12);
  doc.setDrawColor(203,213,225);doc.line(margin,y,pageW-margin,y);gap(10);
  line('Limitations and disclaimer',10,'bold',[100,116,139]);
  line(model.limitations,8,'italic',[100,116,139]);
  return doc;
}
