(function(){
  const rx = /sk-[A-Za-z0-9]{20,}/g;
  const det = {
    name: 'openai', kind: 'api',
    test(text){
      const out = []; for (const m of text.matchAll(rx)) out.push({type:'api', key:'openai', match:m[0], index:m.index??0, severity:'high'});
      return out;
    },
    redact(){ return 'sk-[REDACTED]'; }
  };
  window.SG_DETECTORS.register(det);
})();
