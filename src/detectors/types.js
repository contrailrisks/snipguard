// JSDoc types (for editor hints)
/**
 * @typedef {'api'|'pii'|'code'} DetectionKind
 * @typedef {'low'|'medium'|'high'} Severity
 * @typedef {{type:DetectionKind, key:string, match:string, index:number, severity?:Severity}} Detection
 * @typedef {{ name:string, kind:DetectionKind, test:(text:string, ctx?:any)=>Detection[], redact?:(match:string)=>string }} Detector
 */

// shared namespace
window.SG_DETECTORS = window.SG_DETECTORS || {
  list: [],
  register(d)      { this.list.push(d); },
  unregister(name) { this.list = this.list.filter(d => d.name !== name); }
};
