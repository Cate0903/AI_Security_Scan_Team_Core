'''
Advanced Risk Scoring System
'''


class RiskScorer:
    '''Calculate advanced risk score'''
    
    def __init__(self):
        '''Initialize scoring weights'''
        self.attack_vector_weights = {
            'NETWORK': 1.0, 'ADJACENT': 0.8, 'ADJACENT_NETWORK': 0.8,
            'LOCAL': 0.5, 'PHYSICAL': 0.2
        }
        
        self.attack_complexity_weights = {
            'LOW': 1.0, 'HIGH': 0.7
        }
        
        self.privileges_weights = {
            'NONE': 1.0, 'LOW': 0.8, 'HIGH': 0.5
        }
        
        self.user_interaction_weights = {
            'NONE': 1.0, 'REQUIRED': 0.7
        }
        
        self.impact_weights = {
            'HIGH': 1.0, 'LOW': 0.5, 'NONE': 0.0
        }
        
        self.context_weights = {
            'public_facing': 1.2,
            'internal': 1.0,
            'isolated': 0.8
        }
    
    def calculate_risk_score(self, vuln_data, ml_prediction=None, context='internal'):
        '''Calculate comprehensive risk score'''
        base_score = float(vuln_data.get('cvss_score', 5.0))
        
        if ml_prediction and ml_prediction.get('ml_available'):
            ml_confidence = ml_prediction.get('confidence', 0.7)
            base_score *= (0.85 + (ml_confidence * 0.3))
        
        exploit_score = self._calculate_exploitability(vuln_data)
        impact_score = self._calculate_impact(vuln_data)
        context_mult = self.context_weights.get(context, 1.0)
        
        risk = base_score * exploit_score * impact_score * context_mult
        
        return max(0.0, min(10.0, risk))
    
    def _calculate_exploitability(self, vuln_data):
        '''Calculate exploitability score'''
        av = vuln_data.get('attack_vector', 'LOCAL').upper()
        av_weight = self.attack_vector_weights.get(av, 0.5)
        
        ac = vuln_data.get('attack_complexity', 'HIGH').upper()
        ac_weight = self.attack_complexity_weights.get(ac, 0.7)
        
        pr = vuln_data.get('privileges_required', 'LOW').upper()
        pr_weight = self.privileges_weights.get(pr, 0.8)
        
        ui = vuln_data.get('user_interaction', 'NONE').upper()
        ui_weight = self.user_interaction_weights.get(ui, 1.0)
        
        return (av_weight + ac_weight + pr_weight + ui_weight) / 4.0
    
    def _calculate_impact(self, vuln_data):
        '''Calculate impact score'''
        conf = vuln_data.get('confidentiality_impact', 'NONE').upper()
        conf_weight = self.impact_weights.get(conf, 0.0)
        
        integ = vuln_data.get('integrity_impact', 'NONE').upper()
        integ_weight = self.impact_weights.get(integ, 0.0)
        
        avail = vuln_data.get('availability_impact', 'NONE').upper()
        avail_weight = self.impact_weights.get(avail, 0.0)
        
        impact_score = (conf_weight + integ_weight + avail_weight) / 3.0
        
        if impact_score == 0.0:
            impact_score = 0.3
        
        return impact_score
    
    def get_priority(self, risk_score):
        '''Get priority 1-4'''
        if risk_score >= 9.0:
            return 1
        elif risk_score >= 7.0:
            return 2
        elif risk_score >= 4.0:
            return 3
        else:
            return 4
    
    def get_priority_label(self, priority):
        '''Get priority label'''
        labels = {1: 'URGENTE', 2: 'ALTO', 3: 'MEDIO', 4: 'BASSO'}
        return labels.get(priority, 'MEDIO')
    
    def get_timeframe(self, priority):
        '''Get recommended timeframe'''
        timeframes = {
            1: '24 ore',
            2: '1 settimana',
            3: '1 mese',
            4: 'Ciclo manutenzione'
        }
        return timeframes.get(priority, '1 mese')


if __name__ == '__main__':
    # Test
    scorer = RiskScorer()
    
    test = {
        'cvss_score': 9.8,
        'attack_vector': 'NETWORK',
        'attack_complexity': 'LOW',
        'privileges_required': 'NONE',
        'user_interaction': 'NONE',
        'confidentiality_impact': 'HIGH',
        'integrity_impact': 'HIGH',
        'availability_impact': 'HIGH'
    }
    
    risk = scorer.calculate_risk_score(test)
    priority = scorer.get_priority(risk)
    
    print(f"Risk Score: {risk:.2f}/10")
    print(f"Priority: {priority} ({scorer.get_priority_label(priority)})")
