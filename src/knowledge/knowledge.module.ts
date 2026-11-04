import { Global, Module } from '@nestjs/common';
import { KnowledgeService } from './knowledge.service';

@Global()
@Module({ providers: [KnowledgeService], exports: [KnowledgeService] })
export class KnowledgeModule {}
