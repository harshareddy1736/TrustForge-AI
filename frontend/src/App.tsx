import { useEffect, useMemo, useState } from 'react'
import type { FormEvent, ReactNode } from 'react'
import { Activity, ArrowUpRight, Boxes, CircleAlert, Github, Plus, ShieldCheck, Shield, Sparkles, LayoutDashboard, FolderGit2, PackageSearch, Search, Play, Download, RefreshCw, Trash2, FileWarning, ExternalLink } from 'lucide-react'
import { severityClass } from './security'

type Project = {id:number;name:string;repositoryUrl:string;provider:string;createdAt:string}
type Scan = {id:number;projectId:number;status:string;findingCount:number;dependencyCount:number;riskScore:number;createdAt:string}
type Finding = {type:string;title:string;severity:string;packageName?:string|null;installedVersion?:string|null;cve?:string|null;advisoryId?:string|null;summary:string;filePath?:string|null;lineNumber?:number|null;evidence:string;source:string;references:string[];cvssScore?:number|null;cvssVector?:string|null;fixedVersions?:string[];affectedRanges?:string[];recommendation?:string;published?:string|null;modified?:string|null;riskContribution?:number}
type ScanDetail = {repository:string;scanStatus:string;scannedAt?:string;filesInspected:number;manifests:string[];dependencyCount:number;dependencies:{name:string;version:string;ecosystem:string}[];findings:Finding[];severityCounts:Record<string,number>;riskScore:number;riskLevel?:string;riskBreakdown?:{pointsBySeverity:Record<string,number>;totalBeforeCap:number};topRecommendations?:string[];riskScoreNote:string;enrichmentWarnings:string[]}
type Page='overview'|'repositories'|'findings'|'dependencies'|'scans'
const API=import.meta.env.VITE_API_URL??'http://localhost:8080'
const nav:{id:Page;label:string;icon:typeof Activity}[]=[
 {id:'overview',label:'Overview',icon:LayoutDashboard},{id:'repositories',label:'Repositories',icon:FolderGit2},
 {id:'findings',label:'Security findings',icon:Shield},{id:'dependencies',label:'Dependencies',icon:Boxes},{id:'scans',label:'Scan history',icon:Activity}
]
export default function App(){
 const [page,setPage]=useState<Page>('overview')
 const [projects,setProjects]=useState<Project[]>([])
 const [scans,setScans]=useState<Scan[]>([])
 const [details,setDetails]=useState<Record<number,ScanDetail>>({})
 const [selectedScan,setSelectedScan]=useState<number|null>(null)
 const [name,setName]=useState(''); const [url,setUrl]=useState('')
 const [message,setMessage]=useState(''); const [error,setError]=useState('')
 const [busy,setBusy]=useState<number|null>(null); const [apiOnline,setApiOnline]=useState(false)
 const [search,setSearch]=useState('')
 const [loading,setLoading]=useState(true)
 async function loadAll(){
  setLoading(true);setError('')
  try{
   const [h,p,s]=await Promise.all([fetch(`${API}/api/health`),fetch(`${API}/api/projects`),fetch(`${API}/api/scans`)])
   setApiOnline(h.ok); if(!p.ok||!s.ok)throw new Error('Could not load workspace data')
   setProjects(await p.json());setScans(await s.json())
  }catch(e){setApiOnline(false);setError(e instanceof Error?e.message:'Backend is unavailable')}
  finally{setLoading(false)}
 }
 useEffect(()=>{void loadAll()},[])
 async function addProject(e:FormEvent){
  e.preventDefault();setBusy(-1);setError('');setMessage('')
  try{const r=await fetch(`${API}/api/projects`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,repositoryUrl:url})});const b=await r.json();if(!r.ok)throw new Error(b.message||'Could not register repository');setProjects(v=>[b,...v]);setName('');setUrl('');setMessage('Repository registered successfully.')}
  catch(e){setError(e instanceof Error?e.message:'Registration failed')}finally{setBusy(null)}
 }
 async function runScan(project:Project){
  setBusy(project.id);setError('');setMessage(`Scanning ${project.name}. This can take a little while while OSV is queried.`)
  try{const r=await fetch(`${API}/api/projects/${project.id}/scans`,{method:'POST'});const b=await r.json();if(!r.ok)throw new Error(b.message||'Scan failed');setMessage(`Scan #${b.id} completed: ${b.dependencyCount} dependencies and ${b.findingCount} findings.`);await loadAll();await openScan(b.id);setPage('findings')}
  catch(e){setError(e instanceof Error?e.message:'Scan failed');setMessage('')}
  finally{setBusy(null)}
 }
 async function openScan(id:number){
  setSelectedScan(id)
  if(details[id])return
  try{const r=await fetch(`${API}/api/scans/${id}`);if(!r.ok)throw new Error('Could not load scan');const d=await r.json();setDetails(v=>({...v,[id]:d}))}
  catch(e){setError(e instanceof Error?e.message:'Could not load scan')}
 }
 async function deleteProject(id:number){
  if(!window.confirm('Delete this repository from the workspace? Existing scan records are retained.'))return
  try{const r=await fetch(`${API}/api/projects/${id}`,{method:'DELETE'});if(!r.ok)throw new Error('Could not delete repository');setProjects(v=>v.filter(p=>p.id!==id));setMessage('Repository removed.')}
  catch(e){setError(e instanceof Error?e.message:'Delete failed')}
 }
 async function downloadSbom(id:number){
  try{const r=await fetch(`${API}/api/scans/${id}/sbom`);if(!r.ok)throw new Error('SBOM export failed');const blob=await r.blob();const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=`trustforge-scan-${id}-sbom.cdx.json`;a.click();URL.revokeObjectURL(a.href)}
  catch(e){setError(e instanceof Error?e.message:'SBOM export failed')}
 }
 async function downloadReport(id:number){
  try{const r=await fetch(`${API}/api/scans/${id}/report`);if(!r.ok)throw new Error('Security report export failed');const blob=await r.blob();const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=`trustforge-scan-${id}-report.md`;a.click();URL.revokeObjectURL(a.href)}
  catch(e){setError(e instanceof Error?e.message:'Security report export failed')}
 }
 const allFindings=useMemo(()=>Object.entries(details).flatMap(([id,d])=>d.findings.map(f=>({...f,scanId:Number(id),repository:d.repository}))),[details])
 const filteredProjects=projects.filter(p=>`${p.name} ${p.repositoryUrl}`.toLowerCase().includes(search.toLowerCase()))
 const latest=selectedScan?details[selectedScan]:undefined
 const latestScans=scans.slice(0,5)
 function heading(kicker:string,title:string,desc:string){return <div className="page-heading"><span className="eyebrow">{kicker}</span><h2>{title}</h2><p>{desc}</p></div>}
 return <div className="app-shell">
  <aside className="sidebar"><div className="brand"><div className="brand-mark"><ShieldCheck size={21}/></div><span>trustforge<span className="brand-ai">.ai</span></span></div><div className="workspace-label">WORKSPACE</div>
   <nav aria-label="Main navigation">{nav.map(item=>{const I=item.icon;return <button key={item.id} className={`nav-item ${page===item.id?'nav-active':''}`} onClick={()=>{setPage(item.id);setError('');setSearch('')}}><I size={17}/><span>{item.label}</span></button>})}</nav>
   <div className="sidebar-bottom"><div className="avatar">TF</div><div><strong>Local workspace</strong><small>Developer environment</small></div></div>
  </aside>
  <main className="main">
   <header className="topbar"><div><span className="eyebrow">SECURITY COMMAND CENTER</span><h1>{nav.find(n=>n.id===page)?.label}</h1></div><div className="top-actions"><div className="system-status"><span className={apiOnline?'status-dot online':'status-dot'}/>API {apiOnline?'connected':'offline'}</div><button className="icon-button" title="Refresh workspace" onClick={()=>void loadAll()}><RefreshCw size={15}/></button></div></header>
   {error&&<div className="alert error"><CircleAlert size={16}/>{error}</div>}{message&&<div className="alert info">{message}</div>}
   {page==='overview'&&<>
    <section className="welcome"><div><div className="welcome-kicker"><Sparkles size={14}/> SOFTWARE SUPPLY CHAIN INTELLIGENCE</div><h2>Know what ships.<br/><span>Understand what’s at risk.</span></h2><p>Scan public GitHub repositories for dependency advisories, exposed secrets and selected container configuration risks.</p></div><div className="welcome-art"><div className="orbit orbit-one"/><div className="orbit orbit-two"/><div className="shield-large"><ShieldCheck size={58}/></div><div className="orbit-dot dot-one"/><div className="orbit-dot dot-two"/></div></section>
    <section className="metric-grid"><article className="metric-card"><div className="metric-icon"><Github size={18}/></div><span>Repositories</span><strong>{projects.length}</strong><small>Registered in workspace</small></article><article className="metric-card"><div className="metric-icon purple"><FileWarning size={18}/></div><span>Completed scans</span><strong>{scans.length}</strong><small>Stored scan records</small></article><article className="metric-card"><div className="metric-icon green"><ShieldCheck size={18}/></div><span>Latest risk score</span><strong>{scans.length?scans[0].riskScore+'/100':'Pending'}</strong><small>Heuristic priority score</small></article></section>
    <section className="content-grid"><article className="panel"><div className="panel-heading"><div><span className="eyebrow">ASSET INVENTORY</span><h3>Your repositories</h3></div><span className="count-pill">{projects.length} total</span></div>{projects.length===0?<Empty icon={<Github size={24}/>} title="No repositories registered" text="Add a public GitHub repository to begin."/>:<div className="repo-list">{projects.slice(0,4).map(p=><RepoRow key={p.id} project={p} onScan={runScan} busy={busy===p.id}/>)}</div>}<button className="text-button" onClick={()=>setPage('repositories')}>View all repositories <ArrowUpRight size={14}/></button></article>
    <article className="panel add-panel"><div className="panel-heading"><div><span className="eyebrow">GET STARTED</span><h3>Connect a repository</h3></div><div className="plus-icon"><Plus size={18}/></div></div><p className="form-intro">Public GitHub repositories only in this MVP. Repository code is inspected, never executed.</p><form onSubmit={addProject}><label>PROJECT NAME</label><input value={name} onChange={e=>setName(e.target.value)} placeholder="e.g. payments-api" required maxLength={120}/><label>GITHUB REPOSITORY URL</label><input value={url} onChange={e=>setUrl(e.target.value)} placeholder="https://github.com/owner/repository" required type="url"/><button disabled={busy!==null}><Plus size={16}/>{busy===-1?'Adding…':'Add repository'}</button></form></article></section>
    <section className="panel recent-panel"><div className="panel-heading"><div><span className="eyebrow">ACTIVITY</span><h3>Recent scans</h3></div><button className="text-button" onClick={()=>setPage('scans')}>All scans <ArrowUpRight size={14}/></button></div><ScanTable scans={latestScans} onOpen={id=>{void openScan(id);setPage('findings')}} onSbom={downloadSbom} onReport={downloadReport}/></section>
   </>}
   {page==='repositories'&&<>{heading('CONNECTED ASSETS','Repository inventory','Register, inspect and scan public GitHub repositories.')}<div className="panel"><div className="search-wrap"><Search size={16}/><input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search repositories…"/></div>{filteredProjects.length===0?<Empty icon={<Github size={24}/>} title="No matching repositories" text="Try another search or register a repository from Overview."/>:<div className="repo-list">{filteredProjects.map(p=><RepoRow key={p.id} project={p} onScan={runScan} onDelete={deleteProject} busy={busy===p.id}/>)}</div>}</div></>}
   {page==='findings'&&<>{heading('RISK & REMEDIATION','Security findings','Findings are loaded from completed scans. Verify each result before acting.')}<div className="panel"><div className="panel-heading"><div><span className="eyebrow">SCAN RESULT</span><h3>{latest?`Findings — ${latest.repository}`:'Choose a completed scan'}</h3></div>{latest&&<div className="export-actions"><button className="secondary-button" onClick={()=>selectedScan&&downloadReport(selectedScan)}><Download size={14}/> Security report</button><button className="secondary-button" onClick={()=>selectedScan&&downloadSbom(selectedScan)}><Download size={14}/> Export SBOM</button></div>}</div>{scans.length===0?<Empty icon={<Shield size={24}/>} title="No findings yet" text="Run a repository scan to populate this workspace."/>:<><div className="scan-picker">{scans.map(s=><button key={s.id} className={`scan-chip ${selectedScan===s.id?'selected':''}`} onClick={()=>void openScan(s.id)}>Scan #{s.id} · {s.findingCount} findings</button>)}</div>{latest?<><RiskSummary detail={latest}/><FindingsTable findings={latest.findings}/></>:<Empty icon={<FileWarning size={24}/>} title="Select a scan" text="Choose a scan above to view its findings."/ >}</>}</div></>}
   {page==='dependencies'&&<>{heading('SOFTWARE COMPOSITION','Dependency inventory','Packages discovered in repository manifests, with ecosystem and exact version.')}<div className="panel">{latest?<><div className="panel-heading"><div><span className="eyebrow">COMPONENT INVENTORY</span><h3>{latest.repository}</h3></div><button className="secondary-button" onClick={()=>selectedScan&&downloadSbom(selectedScan)}><Download size={14}/> CycloneDX SBOM</button></div><div className="table-wrap"><table><thead><tr><th>PACKAGE</th><th>VERSION</th><th>ECOSYSTEM</th></tr></thead><tbody>{latest.dependencies.map((d,i)=><tr key={`${d.ecosystem}-${d.name}-${i}`}><td>{d.name}</td><td>{d.version}</td><td>{d.ecosystem}</td></tr>)}</tbody></table></div></>:<Empty icon={<PackageSearch size={24}/>} title="No dependency inventory selected" text="Run a scan and select it in Security findings to view discovered packages."/>}</div></>}
   {page==='scans'&&<>{heading('SCAN ACTIVITY','Scan history','Every completed repository scan is stored locally for review and SBOM export.')}<div className="panel"><ScanTable scans={scans} onOpen={id=>{void openScan(id);setPage('findings')}} onSbom={downloadSbom} onReport={downloadReport}/></div></>}
   <footer>TRUSTFORGE AI <span>•</span> RELEASE 1.1.0 <span>•</span> Evidence-first supply-chain security intelligence</footer>
  </main>
 </div>
}
function Empty({icon,title,text}:{icon:ReactNode;title:string;text:string}){return <div className="empty-state"><div className="empty-icon">{icon}</div><strong>{title}</strong><p>{text}</p></div>}
function RepoRow({project,onScan,busy,onDelete}:{project:Project;onScan:(p:Project)=>void;busy:boolean;onDelete?:(id:number)=>void}){return <div className="repo-row"><div className="repo-icon"><Github size={18}/></div><div className="repo-info"><strong>{project.name}</strong><a href={project.repositoryUrl} target="_blank" rel="noreferrer">{project.repositoryUrl}<ExternalLink size={12}/></a></div><button className="small-action" disabled={busy} onClick={()=>onScan(project)}><Play size={13}/>{busy?'Scanning':'Scan now'}</button>{onDelete&&<button className="danger-icon" title="Delete repository" onClick={()=>onDelete(project.id)}><Trash2 size={14}/></button>}</div>}
function ScanTable({scans,onOpen,onSbom,onReport}:{scans:Scan[];onOpen:(id:number)=>void;onSbom:(id:number)=>void;onReport:(id:number)=>void}){if(!scans.length)return <Empty icon={<Activity size={24}/>} title="No scans completed" text="Start a scan from a repository to see scan history."/>;return <div className="table-wrap"><table><thead><tr><th>SCAN</th><th>STATUS</th><th>DEPENDENCIES</th><th>FINDINGS</th><th>RISK</th><th>ACTIONS</th></tr></thead><tbody>{scans.map(s=><tr key={s.id}><td>#{s.id}</td><td><span className="inventory-tag">{s.status}</span></td><td>{s.dependencyCount}</td><td>{s.findingCount}</td><td>{s.riskScore}/100</td><td><button className="table-action" onClick={()=>onOpen(s.id)}>Details</button><button className="table-action" onClick={()=>onSbom(s.id)}>SBOM</button><button className="table-action" onClick={()=>onReport(s.id)}>Report</button></td></tr>)}</tbody></table></div>}
function RiskSummary({detail}:{detail:ScanDetail}){
 const levels=['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN']
 const total=Math.max(1,detail.findings.length)
 return <section className="risk-summary">
  <div className="risk-summary-top"><div><span className="eyebrow">PRIORITIZATION</span><strong className="risk-value">{detail.riskScore}<small>/100</small></strong><span className={`risk-level risk-${(detail.riskLevel||'unknown').toLowerCase()}`}>{detail.riskLevel||'UNCLASSIFIED'}</span></div><p>{detail.riskScoreNote}</p></div>
  <div className="severity-breakdown">{levels.map(level=>{const count=detail.severityCounts?.[level]||0;return <div className="severity-row" key={level}><span className={severityClass(level)}>{level}</span><div className="severity-track"><i className={`severity-fill fill-${level.toLowerCase()}`} style={{width:`${(count/total)*100}%`}}/></div><strong>{count}</strong></div>})}</div>
  {detail.topRecommendations?.length?<div className="recommendation-list"><strong>Suggested next actions</strong><ul>{detail.topRecommendations.slice(0,5).map((item,i)=><li key={i}>{item}</li>)}</ul></div>:null}
  {detail.enrichmentWarnings?.length?<div className="warning-note"><strong>Enrichment warnings</strong>{detail.enrichmentWarnings.map((warning,i)=><p key={i}>{warning}</p>)}</div>:null}
 </section>
}
function FindingsTable({findings}:{findings:Finding[]}){
 if(!findings.length)return <Empty icon={<ShieldCheck size={24}/>} title="No findings returned" text="No supported advisory, secret-pattern or Dockerfile findings were detected in this scan. This is not a guarantee of security."/>
 return <div className="table-wrap"><table><thead><tr><th>SEVERITY</th><th>FINDING & EVIDENCE</th><th>PACKAGE / LOCATION</th><th>SOURCE</th></tr></thead><tbody>{findings.map((f,i)=><tr key={`${f.advisoryId||f.cve||f.type}-${i}`}><td><span className={severityClass(f.severity)}>{f.severity}</span>{f.cvssScore!==null&&f.cvssScore!==undefined?<small className="cell-sub">CVSS {f.cvssScore.toFixed(1)}</small>:null}</td><td><strong>{f.title}</strong><small className="cell-sub">{f.advisoryId||f.cve||f.type}</small><small className="cell-sub">{f.summary?.slice(0,260)}</small>{f.affectedRanges?.map((range,j)=><small className="cell-sub" key={j}>Affected range: {range}</small>)}{f.fixedVersions?.length?<small className="fix-version">Fixed in: {f.fixedVersions.join(', ')}</small>:null}{f.recommendation?<div className="recommendation-text">{f.recommendation}</div>:null}{f.evidence?<small className="cell-sub">Evidence: {f.evidence}</small>:null}{f.references?.slice(0,2).map(ref=><a className="advisory-link" key={`${ref}-${i}`} href={ref} target="_blank" rel="noreferrer">Advisory <ExternalLink size={11}/></a>)}</td><td>{f.packageName?`${f.packageName}@${f.installedVersion}`:f.filePath||'—'}{f.lineNumber?`:${f.lineNumber}`:''}</td><td>{f.source}</td></tr>)}</tbody></table></div>
}
