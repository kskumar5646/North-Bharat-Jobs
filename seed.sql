INSERT OR IGNORE INTO settings(key,value) VALUES
('site_name','North Bharat Jobs'),
('retention_days','365'),
('official_retry_limit_daily','20'),
('official_retry_interval_minutes','5'),
('portal_count_required','2');

INSERT OR IGNORE INTO sources(name,role,fallback_key,base_url,allowed_domains,adapter,priority) VALUES
('UPSC','official','upsc','https://upsc.gov.in/','upsc.gov.in','generic',10),
('SSC','official','ssc','https://ssc.gov.in/','ssc.gov.in','generic',10),
('Bihar PSC','official','bpsc','https://www.bpsc.bih.nic.in/','bpsc.bih.nic.in','generic',20),
('Jharkhand PSC','official','jpsc','https://www.jpsc.gov.in/','jpsc.gov.in','generic',20),
('West Bengal PSC','official','wbpsc','https://psc.wb.gov.in/','psc.wb.gov.in','generic',20),
('Uttarakhand PSC','official','ukpsc','https://psc.uk.gov.in/','psc.uk.gov.in','generic',20),
('Uttar Pradesh PSC','official','uppsc','https://uppsc.up.nic.in/','uppsc.up.nic.in','generic',20),
('Madhya Pradesh PSC','official','mppsc','https://mppsc.mp.gov.in/','mppsc.mp.gov.in','generic',20),
('Maharashtra PSC','official','mpsc','https://mpsc.gov.in/','mpsc.gov.in','generic',20),
('Gujarat PSC','official','gpsc','https://gpsc.gujarat.gov.in/','gpsc.gujarat.gov.in','generic',20),
('Haryana PSC','official','hpsc','https://hpsc.gov.in/','hpsc.gov.in','generic',20),
('Punjab PSC','official','ppsc','https://ppsc.gov.in/','ppsc.gov.in','generic',20),
('Delhi Subordinate Services','official','dsssb','https://dsssb.delhi.gov.in/','dsssb.delhi.gov.in','generic',30),
('CBSE','official','cbse','https://www.cbse.gov.in/','cbse.gov.in','generic',30),
('NTA','official','nta','https://www.nta.ac.in/','nta.ac.in','generic',30),
('Indian Railways','official','railway','https://indianrailways.gov.in/','indianrailways.gov.in;rrbapply.gov.in','generic',20),
('Indian Bank','official','indian-bank','https://www.indianbank.in/','indianbank.in','generic',30),
('SBI Careers','official','sbi','https://sbi.co.in/web/careers','sbi.co.in','generic',30),
('RBI','official','rbi','https://www.rbi.org.in/','rbi.org.in','generic',30),
('India Post','official','indiapost','https://www.indiapost.gov.in/','indiapost.gov.in','generic',30),
('Defence Jobs','official','defence','https://www.mod.gov.in/','mod.gov.in','generic',40);

-- Portal slots are intentionally configurable. Replace these URLs from Admin > Sources.
INSERT OR IGNORE INTO sources(name,role,fallback_key,base_url,allowed_domains,adapter,priority) VALUES
('Portal 1','portal','*','https://portal-1.example/','portal-1.example','generic',90),
('Portal 2','portal','*','https://portal-2.example/','portal-2.example','generic',91);

UPDATE sources SET enabled=0 WHERE role='portal';
