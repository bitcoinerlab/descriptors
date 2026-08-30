import * as core from '@bitcoinerlab/descriptors-core';
import { createScureLib } from '@bitcoinerlab/descriptors-core/scure';

/** Backend-bound descriptor primitives shared by this preset package. */
export const bound = core.DescriptorsFactory(createScureLib());
