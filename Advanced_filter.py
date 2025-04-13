#!/usr/bin/env python3
import re
import os
import shutil
import datetime
import ipaddress
import argparse
from collections import Counter, defaultdict

class SnortAlertOptimizer:
    def __init__(self, alert_file, rules_file, threshold_file=None, backup=True):
        self.alert_file = alert_file
        self.rules_file = rules_file
        self.threshold_file = threshold_file
        self.backup = backup
        
        # Configuration des filtres
        self.ignored_ips = set()
        self.ignored_networks = set()
        self.ignored_messages = set()
        self.ignored_sids = set()
        
        # Statistiques
        self.alert_stats = defaultdict(Counter)
        self.ip_stats = defaultdict(Counter)
        self.time_stats = defaultdict(Counter)
        
        # Règles et seuils
        self.rules = {}
        self.thresholds = {}
        
    def load_whitelist(self, whitelist_file):
        """Charge une liste d'IPs et de réseaux à ignorer"""
        if not os.path.exists(whitelist_file):
            print(f"Le fichier {whitelist_file} n'existe pas")
            return
            
        with open(whitelist_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                    
                try:
                    # Vérifier si c'est un réseau CIDR
                    if '/' in line:
                        network = ipaddress.ip_network(line, strict=False)
                        self.ignored_networks.add(network)
                    else:
                        # Sinon c'est une IP individuelle
                        ip = ipaddress.ip_address(line)
                        self.ignored_ips.add(str(ip))
                except ValueError:
                    print(f"Adresse IP ou réseau invalide: {line}")
        
        print(f"Chargement de {len(self.ignored_ips)} IPs et {len(self.ignored_networks)} réseaux à ignorer")
    
    def is_ip_ignored(self, ip_str):
        """Vérifie si une IP doit être ignorée"""
        if ip_str in self.ignored_ips:
            return True
            
        try:
            ip = ipaddress.ip_address(ip_str)
            for network in self.ignored_networks:
                if ip in network:
                    return True
        except ValueError:
            pass
            
        return False
        
    def parse_alert_file(self):
        """Analyse le fichier d'alertes pour identifier les tendances"""
        alerts = []
        sid_pattern = re.compile(r'\[\*\*\] \[(\d+):(\d+):(\d+)\] (.+?) \[\*\*\]')
        ip_pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+)(:\d+)? -> (\d+\.\d+\.\d+\.\d+)(:\d+)?')
        timestamp_pattern = re.compile(r'(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)')
        
        print(f"Analyse du fichier d'alertes: {self.alert_file}")
        
        try:
            with open(self.alert_file, 'r', encoding='utf-8', errors='ignore') as f:
                current_alert = {}
                lines = []
                
                for line in f:
                    line = line.strip()
                    if not line:
                        if current_alert and lines:
                            current_alert['raw'] = '\n'.join(lines)
                            alerts.append(current_alert)
                        current_alert = {}
                        lines = []
                        continue
                    
                    lines.append(line)
                    
                    # Extraire l'ID de signature
                    sid_match = sid_pattern.search(line)
                    if sid_match:
                        gid, sid, rev = sid_match.groups()[:3]
                        msg = sid_match.group(4)
                        current_alert['gid'] = gid
                        current_alert['sid'] = sid
                        current_alert['rev'] = rev
                        current_alert['msg'] = msg
                        
                        # Mise à jour des statistiques
                        self.alert_stats['sid'][sid] += 1
                        self.alert_stats['msg'][msg] += 1
                    
                    # Extraire les IPs source et destination
                    ip_match = ip_pattern.search(line)
                    if ip_match:
                        src_ip, _, dst_ip, _ = ip_match.groups()
                        current_alert['src_ip'] = src_ip
                        current_alert['dst_ip'] = dst_ip
                        
                        # Mise à jour des statistiques
                        self.ip_stats['src'][src_ip] += 1
                        self.ip_stats['dst'][dst_ip] += 1
                    
                    # Extraire le timestamp
                    time_match = timestamp_pattern.search(line)
                    if time_match:
                        timestamp = time_match.group(1)
                        current_alert['timestamp'] = timestamp
                        
                        # Extraire l'heure pour les statistiques
                        hour = timestamp.split('-')[1].split(':')[0]
                        self.time_stats['hour'][hour] += 1
                
                # Ne pas oublier la dernière alerte
                if current_alert and lines:
                    current_alert['raw'] = '\n'.join(lines)
                    alerts.append(current_alert)
        except Exception as e:
            print(f"Erreur lors de la lecture du fichier d'alertes: {e}")
            return []
            
        print(f"{len(alerts)} alertes analysées")
        self.analyze_statistics()
        
        return alerts
        
    def analyze_statistics(self):
        """Analyse les statistiques pour suggérer des optimisations"""
        # Top 10 des SIDs qui génèrent le plus d'alertes
        print("\nTop 10 des règles qui génèrent le plus d'alertes:")
        for sid, count in self.alert_stats['sid'].most_common(10):
            msg = next((m for m, c in self.alert_stats['msg'].items() if sid in m), "Message inconnu")
            print(f"SID {sid}: {count} alertes - {msg}")
        
        # Top 10 des IPs sources qui génèrent le plus d'alertes
        print("\nTop 10 des IPs sources qui génèrent le plus d'alertes:")
        for ip, count in self.ip_stats['src'].most_common(10):
            print(f"{ip}: {count} alertes")
            
        # Distribution des alertes par heure
        print("\nDistribution des alertes par heure:")
        for hour in sorted(self.time_stats['hour'].keys()):
            count = self.time_stats['hour'][hour]
            print(f"{hour}h: {count} alertes")
    
    def parse_rules_file(self):
        """Charge et analyse le fichier de règles Snort"""
        if not os.path.exists(self.rules_file):
            print(f"Le fichier de règles {self.rules_file} n'existe pas")
            return
            
        with open(self.rules_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                    
                # Extraire le SID de la règle
                sid_match = re.search(r'sid\s*:\s*(\d+)\s*;', line)
                if sid_match:
                    sid = sid_match.group(1)
                    self.rules[sid] = line
    
    def generate_optimization_report(self, alerts):
        """Génère un rapport d'optimisation basé sur l'analyse des alertes"""
        # Identifier les SID qui génèrent beaucoup d'alertes
        high_frequency_sids = [sid for sid, count in self.alert_stats['sid'].most_common() if count > 100]
        
        # Identifier les IPs qui génèrent beaucoup d'alertes
        high_frequency_ips = [ip for ip, count in self.ip_stats['src'].most_common() if count > 50]
        
        recommendations = []
        
        # Recommandations pour les règles fréquemment déclenchées
        for sid in high_frequency_sids:
            if sid in self.rules:
                recommendations.append({
                    'type': 'rule',
                    'sid': sid,
                    'count': self.alert_stats['sid'][sid],
                    'action': 'threshold',
                    'suggestion': f"event_filter gen_id 1, sig_id {sid}, type threshold, track by_src, count 5, seconds 60"
                })
        
        # Recommandations pour les IPs à potentiellement ignorer
        for ip in high_frequency_ips:
            if not self.is_ip_ignored(ip):
                recommendations.append({
                    'type': 'ip',
                    'ip': ip,
                    'count': self.ip_stats['src'][ip],
                    'action': 'suppress',
                    'suggestion': f"suppressions suivantes pourraient réduire les faux positifs pour l'IP {ip}"
                })
        
        return recommendations
    
    def update_threshold_file(self, recommendations):
        """Met à jour le fichier threshold.conf avec les nouvelles recommandations"""
        if not self.threshold_file:
            print("Aucun fichier de seuil spécifié, impossible de mettre à jour les seuils")
            return
            
        if not os.path.exists(self.threshold_file):
            print(f"Le fichier de seuil {self.threshold_file} n'existe pas")
            return
            
        # Créer une sauvegarde si nécessaire
        if self.backup:
            backup_file = f"{self.threshold_file}.bak.{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
            shutil.copy2(self.threshold_file, backup_file)
            print(f"Sauvegarde du fichier de seuil créée: {backup_file}")
        
        # Chargement du fichier de seuil existant
        with open(self.threshold_file, 'r') as f:
            thresholds = f.readlines()
        
        # Ajouter les nouvelles recommandations
        with open(self.threshold_file, 'a') as f:
            f.write("\n# Règles ajoutées automatiquement le " + 
                   datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S') + "\n")
            
            for rec in recommendations:
                if rec['type'] == 'rule' and rec['action'] == 'threshold':
                    # Vérifier si cette règle existe déjà
                    if not any(f"sig_id {rec['sid']}" in line for line in thresholds):
                        f.write(rec['suggestion'] + "\n")
                        print(f"Ajout d'un seuil pour SID {rec['sid']}")
        
        print(f"Fichier de seuil mis à jour: {self.threshold_file}")
    
    def update_rules_file(self, recommendations):
        """Met à jour le fichier de règles en fonction des recommandations"""
        if not os.path.exists(self.rules_file):
            print(f"Le fichier de règles {self.rules_file} n'existe pas")
            return
            
        # Créer une sauvegarde si nécessaire
        if self.backup:
            backup_file = f"{self.rules_file}.bak.{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
            shutil.copy2(self.rules_file, backup_file)
            print(f"Sauvegarde du fichier de règles créée: {backup_file}")
        
        with open(self.rules_file, 'r') as f:
            rules = f.readlines()
        
        # Mettre à jour les règles
        updated_rules = []
        for line in rules:
            line_strip = line.strip()
            if not line_strip or line_strip.startswith('#'):
                updated_rules.append(line)
                continue
                
            # Chercher le SID dans la règle
            sid_match = re.search(r'sid\s*:\s*(\d+)\s*;', line_strip)
            if sid_match:
                sid = sid_match.group(1)
                
                # Vérifier si cette règle est dans nos recommandations
                for rec in recommendations:
                    if rec['type'] == 'rule' and rec['sid'] == sid:
                        # Ajouter un commentaire pour indiquer que cette règle a été modifiée
                        updated_rules.append(f"# Règle modifiée automatiquement car générant beaucoup d'alertes\n")
                        
                        # Si la règle est 'alert', la changer en 'drop' ou ajouter un threshold
                        if line_strip.startswith('alert'):
                            new_line = line.replace('alert', 'alert', 1)  # On garde alert mais on pourrait mettre 'drop'
                            updated_rules.append(new_line)
                            print(f"Règle SID {sid} modifiée")
                        else:
                            updated_rules.append(line)
                        break
                else:
                    # Si aucune recommandation pour cette règle
                    updated_rules.append(line)
            else:
                updated_rules.append(line)
        
        # Écrire les règles mises à jour
        with open(self.rules_file, 'w') as f:
            f.writelines(updated_rules)
            
        print(f"Fichier de règles mis à jour: {self.rules_file}")
    
    def create_whitelist_updates(self, recommendations):
        """Crée un fichier avec les IPs à potentiellement ajouter à la liste blanche"""
        whitelist_file = "snort_whitelist_recommendations.txt"
        
        with open(whitelist_file, 'w') as f:
            f.write("# IPs recommandées pour la liste blanche - " + 
                   datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S') + "\n")
            f.write("# Format: IP/réseau [commentaire]\n\n")
            
            for rec in recommendations:
                if rec['type'] == 'ip':
                    f.write(f"{rec['ip']} # {rec['count']} alertes\n")
        
        print(f"Recommandations de liste blanche écrites dans: {whitelist_file}")
    
    def run(self, whitelist_file=None, apply_changes=False):
        """Exécute l'optimisation complète"""
        # Charger la liste blanche si fournie
        if whitelist_file:
            self.load_whitelist(whitelist_file)
        
        # Analyser les alertes
        alerts = self.parse_alert_file()
        
        # Charger les règles
        self.parse_rules_file()
        
        # Générer des recommandations
        recommendations = self.generate_optimization_report(alerts)
        
        # Afficher les recommandations
        print("\nRecommandations d'optimisation:")
        for rec in recommendations:
            if rec['type'] == 'rule':
                print(f"- Règle SID {rec['sid']} ({rec['count']} alertes): {rec['action']}")
                print(f"  Suggestion: {rec['suggestion']}")
            elif rec['type'] == 'ip':
                print(f"- IP {rec['ip']} ({rec['count']} alertes): {rec['action']}")
        
        # Appliquer les changements si demandé
        if apply_changes:
            self.update_threshold_file(recommendations)
            self.update_rules_file(recommendations)
        
        # Toujours créer les recommandations de liste blanche
        self.create_whitelist_updates(recommendations)

def main():
    parser = argparse.ArgumentParser(description="Optimiseur d'alertes Snort")
    parser.add_argument('--alert-file', default='/var/log/snort/alert', 
                       help='Chemin vers le fichier d\'alertes Snort')
    parser.add_argument('--rules-file', default='/etc/snort/rules/community.rules',
                       help='Chemin vers le fichier de règles Snort')
    parser.add_argument('--threshold-file', default='/etc/snort/threshold.conf',
                       help='Chemin vers le fichier de seuil Snort')
    parser.add_argument('--whitelist', help='Chemin vers un fichier contenant des IPs à ignorer')
    parser.add_argument('--apply', action='store_true', 
                       help='Appliquer les changements recommandés')
    parser.add_argument('--no-backup', action='store_true',
                       help='Ne pas créer de sauvegarde des fichiers modifiés')
    
    args = parser.parse_args()
    
    optimizer = SnortAlertOptimizer(
        alert_file=args.alert_file,
        rules_file=args.rules_file,
        threshold_file=args.threshold_file,
        backup=not args.no_backup
    )
    
    optimizer.run(whitelist_file=args.whitelist, apply_changes=args.apply)

if __name__ == "__main__":
    main()