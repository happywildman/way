def save_stats(self, working_fast: Dict[str, float], source_configs: Dict[str, List[str]]):
    """Сохраняет статистику с полным анализом по источникам и дубликатам."""
    with open(self.stat_file, 'w', encoding='utf-8') as f:
        # ========== ОСНОВНАЯ СТАТИСТИКА ==========
        f.write("="*70 + "\n")
        f.write("📊 СТАТИСТИКА ПО ИСТОЧНИКАМ ПРОКСИ\n")
        f.write("="*70 + "\n\n")
        
        f.write(f"Дата: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Таймауты: быстрый={self.quick_timeout}c, полный={self.check_timeout}c\n\n")
        
        total_all = 0
        passed_all = 0
        
        sorted_sources = sorted(
            self.source_stats.items(),
            key=lambda x: (x[1]['passed'] / x[1]['total']) if x[1]['total'] > 0 else 0,
            reverse=True
        )
        
        for url, stats in sorted_sources:
            if stats['total'] == 0:
                continue
            
            total_all += stats['total']
            passed_all += stats['passed']
            percent = (stats['passed'] / stats['total'] * 100) if stats['total'] > 0 else 0
            
            f.write(f"📌 {url}\n")
            f.write(f"   Total vless: {stats['total']}\n")
            f.write(f"   ✅ Прошли полный тест: {stats['passed']} ({percent:.1f}%)\n")
            f.write(f"   ⚡ Avg ping: {stats['avg_ping']:.0f}ms\n\n")
        
        f.write("="*70 + "\n")
        f.write("📈 ОБЩАЯ СТАТИСТИКА\n")
        f.write("="*70 + "\n")
        
        total_percent = (passed_all / total_all * 100) if total_all > 0 else 0
        f.write(f"Всего vless серверов: {total_all}\n")
        f.write(f"✅ Прошли полный тест: {passed_all} ({total_percent:.1f}%)\n\n")
        
        # ========== АНАЛИЗ ДУБЛИКАТОВ ==========
        if source_configs:
            f.write("\n" + "="*70 + "\n")
            f.write("🔍 АНАЛИЗ ДУБЛИКАТОВ И УНИКАЛЬНОСТИ ИСТОЧНИКОВ\n")
            f.write("="*70 + "\n\n")
            
            # Собираем все конфиги с привязкой к источникам
            config_sources = defaultdict(set)
            source_totals = defaultdict(int)
            
            for source_url, configs in source_configs.items():
                for config in configs:
                    if config.startswith('vless://'):
                        base_config = re.sub(r'#.*', '', config)
                        config_sources[base_config].add(source_url)
                        source_totals[source_url] += 1
            
            # Считаем уникальные и дублирующиеся для каждого источника
            source_unique = defaultdict(int)
            source_shared = defaultdict(int)
            
            for base_config, sources in config_sources.items():
                for source in sources:
                    if len(sources) == 1:
                        source_unique[source] += 1
                    else:
                        source_shared[source] += 1
            
            # Общая статистика по пулу
            unique_total = len(config_sources)
            total_with_dupes = sum(source_totals.values())
            
            f.write(f"📊 Всего уникальных vless конфигов в пуле: {unique_total:,}\n")
            f.write(f"📊 Всего vless конфигов с учётом дублей: {total_with_dupes:,}\n")
            if unique_total > 0:
                f.write(f"📊 Коэффициент дублирования: {total_with_dupes/unique_total:.2f}x\n\n")
            
            # Таблица источников
            f.write("📌 ДЕТАЛЬНАЯ СТАТИСТИКА ПО ИСТОЧНИКАМ:\n")
            f.write("-" * 120 + "\n")
            f.write("   {:<80} {:>8} {:>8} {:>8} {:>10} {:>10} {:>12}\n".format(
                "Источник", "Всего", "Уник.", "Дублей", "% уник.", "Пинг%", "Статус"
            ))
            f.write("-" * 120 + "\n")
            
            # Сортируем по проценту уникальности
            sorted_for_analysis = sorted(
                source_totals.keys(),
                key=lambda x: (source_unique[x] / source_totals[x]) if source_totals[x] > 0 else 0,
                reverse=True
            )
            
            for source in sorted_for_analysis:
                total = source_totals[source]
                if total == 0:
                    continue
                
                unique = source_unique[source]
                shared = source_shared[source]
                unique_pct = (unique / total * 100)
                
                ping_passed = self.source_stats.get(source, {}).get('passed', 0)
                ping_total = self.source_stats.get(source, {}).get('total', 0)
                ping_pct = (ping_passed / ping_total * 100) if ping_total > 0 else 0
                
                # Определяем статус источника
                if unique_pct >= 70 and ping_pct >= 50:
                    status = "🟢 ОТЛИЧНЫЙ"
                elif unique_pct >= 30 and ping_pct >= 30:
                    status = "🟡 СРЕДНИЙ"
                elif unique_pct >= 15 and ping_pct >= 10:
                    status = "🟠 СОМНИТЕЛЬНЫЙ"
                else:
                    status = "🔴 МУСОР"
                
                short_url = source if len(source) <= 80 else source[:77] + "..."
                
                f.write("   {:<80} {:8d} {:8d} {:8d} {:9.1f}% {:9.1f}%  {}\n".format(
                    short_url, total, unique, shared, unique_pct, ping_pct, status
                ))
            
            # ========== РЕКОМЕНДАЦИИ ==========
            f.write("\n💡 РЕКОМЕНДАЦИИ ПО ОПТИМИЗАЦИИ:\n")
            f.write("-"*70 + "\n")
            
            sources_to_remove = []
            unique_loss = 0
            total_checks = 0
            
            for source in source_totals.keys():
                total = source_totals[source]
                unique = source_unique[source]
                unique_pct = (unique / total * 100) if total > 0 else 0
                ping_pct = self.source_stats.get(source, {}).get('passed', 0) / max(1, self.source_stats.get(source, {}).get('total', 1)) * 100
                
                if unique_pct < 15 or ping_pct < 10:
                    sources_to_remove.append((source, unique, total))
                    unique_loss += unique
                    total_checks += total
            
            if sources_to_remove:
                f.write(f"\n🔴 КАНДИДАТЫ НА УДАЛЕНИЕ ИЗ sources.txt:\n")
                for source, unique, total in sources_to_remove[:5]:
                    short_url = source if len(source) <= 80 else source[:77] + "..."
                    f.write(f"   • {short_url}\n")
                    f.write(f"     (уникальных: {unique}, проверок: {total})\n")
                
                # Расчёт экономии времени
                current_time = total_with_dupes / 43.6
                new_time = (total_with_dupes - total_checks) / 43.6
                
                f.write(f"\n📊 ПОТЕНЦИАЛЬНАЯ ЭКОНОМИЯ:\n")
                f.write(f"   • Удаляется источников: {len(sources_to_remove)}\n")
                f.write(f"   • Потеряется уникальных: {unique_loss} ({unique_loss/unique_total*100:.1f}%)\n")
                f.write(f"   • Освободится проверок: {total_checks} ({total_checks/total_with_dupes*100:.1f}%)\n")
                f.write(f"   • НОВОЕ ВРЕМЯ: ~{new_time:.0f} сек (было {current_time:.0f} сек)\n")
            else:
                f.write("\n✅ Все источники качественные, удалять нечего!\n")
            
            f.write("="*70 + "\n")
