(function(){
  const det = {
    name:'code_heuristic', kind:'code',
    test(text){
      const lines = text.split('\n').length;
      const codey = /(\bclass\b|\bdef\b|\bfunction\b|=>|^import\s|\bpackage\.json\b|^#include|\busing\s)/m.test(text);
      const configFiles = /(pom\.xml|\.csproj|Cargo\.toml|requirements\.txt|package\.json)/i.test(text);
      if ((lines>=25 && codey) || configFiles){
        return [{ type:'code', key: configFiles?'config':'heuristic', match: text.slice(0,80), index:0, severity:'low' }];
      }
      return [];
    }
  };
  window.SG_DETECTORS.register(det);
})();
