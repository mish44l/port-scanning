import unittest
from app import app, RULES, HISTORY, parse_ports, resolve_target, evaluate
class NetGuardTests(unittest.TestCase):
 def setUp(self):
  app.testing=True; self.client=app.test_client(); RULES.clear(); HISTORY.clear()
 def test_ports(self):
  self.assertEqual(parse_ports('22,80-82'),[22,80,81,82])
  with self.assertRaises(ValueError): parse_ports('0')
 def test_public_blocked(self):
  with self.assertRaises(ValueError): resolve_target('8.8.8.8')
 def test_scan_validation(self):
  self.assertEqual(self.client.post('/api/scan',json={'target':'8.8.8.8','ports':'80'}).status_code,400)
 def test_rules_priority(self):
  self.client.post('/api/rules',json={'action':'deny','ip':'192.168.1.0/24','port':'443','protocol':'tcp','priority':10})
  self.client.post('/api/rules',json={'action':'allow','ip':'any','port':'443','protocol':'tcp','priority':100})
  self.assertEqual(evaluate({'ip':'192.168.1.10','port':443,'protocol':'tcp'})['decision'],'deny')
  self.assertEqual(evaluate({'ip':'10.0.0.2','port':443,'protocol':'tcp'})['decision'],'allow')
 def test_edit_delete(self):
  d=self.client.post('/api/rules',json={'action':'deny','ip':'any','port':'80','protocol':'tcp','priority':10}).get_json();rid=d['id']
  self.assertEqual(self.client.put(f'/api/rules/{rid}',json={'action':'allow','ip':'any','port':'80','protocol':'tcp','priority':10}).get_json()['action'],'allow')
  self.assertEqual(self.client.delete(f'/api/rules/{rid}').status_code,200)
  self.assertEqual(len(RULES),0)
 def test_simulate(self):
  d=self.client.post('/api/simulate',json={'ip':'127.0.0.1','port':443,'protocol':'tcp'}).get_json()
  self.assertEqual(d['decision'],'allow')
if __name__=='__main__': unittest.main()
