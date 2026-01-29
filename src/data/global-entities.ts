/**
 * Global Entities Database - Known brands, manufacturers, artists, athletes, celebrities
 * Helps with autocomplete and prevents misspellings
 */

export interface GlobalEntity {
  name: string;
  type: 'manufacturer' | 'brand' | 'artist' | 'athlete' | 'celebrity' | 'designer' | 'company';
  category?: string;
  aliases?: string[];
}

// Watch Brands
const WATCHES: GlobalEntity[] = [
  { name: 'Rolex', type: 'manufacturer', category: 'watches' },
  { name: 'Patek Philippe', type: 'manufacturer', category: 'watches' },
  { name: 'Audemars Piguet', type: 'manufacturer', category: 'watches', aliases: ['AP'] },
  { name: 'Omega', type: 'manufacturer', category: 'watches' },
  { name: 'Cartier', type: 'manufacturer', category: 'watches' },
  { name: 'TAG Heuer', type: 'manufacturer', category: 'watches', aliases: ['Tag Heuer', 'Heuer'] },
  { name: 'Breitling', type: 'manufacturer', category: 'watches' },
  { name: 'IWC Schaffhausen', type: 'manufacturer', category: 'watches', aliases: ['IWC'] },
  { name: 'Jaeger-LeCoultre', type: 'manufacturer', category: 'watches', aliases: ['JLC'] },
  { name: 'Vacheron Constantin', type: 'manufacturer', category: 'watches' },
  { name: 'A. Lange & Söhne', type: 'manufacturer', category: 'watches', aliases: ['Lange'] },
  { name: 'Panerai', type: 'manufacturer', category: 'watches' },
  { name: 'Hublot', type: 'manufacturer', category: 'watches' },
  { name: 'Richard Mille', type: 'manufacturer', category: 'watches' },
  { name: 'Tudor', type: 'manufacturer', category: 'watches' },
  { name: 'Grand Seiko', type: 'manufacturer', category: 'watches' },
  { name: 'Seiko', type: 'manufacturer', category: 'watches' },
  { name: 'Casio', type: 'manufacturer', category: 'watches', aliases: ['G-Shock'] },
  { name: 'Tissot', type: 'manufacturer', category: 'watches' },
  { name: 'Longines', type: 'manufacturer', category: 'watches' },
];

// Sneaker/Footwear Brands
const SNEAKERS: GlobalEntity[] = [
  { name: 'Nike', type: 'manufacturer', category: 'sneakers' },
  { name: 'Air Jordan', type: 'brand', category: 'sneakers', aliases: ['Jordan', 'Jordan Brand'] },
  { name: 'Adidas', type: 'manufacturer', category: 'sneakers' },
  { name: 'Yeezy', type: 'brand', category: 'sneakers' },
  { name: 'New Balance', type: 'manufacturer', category: 'sneakers' },
  { name: 'Puma', type: 'manufacturer', category: 'sneakers' },
  { name: 'Reebok', type: 'manufacturer', category: 'sneakers' },
  { name: 'Converse', type: 'manufacturer', category: 'sneakers' },
  { name: 'Vans', type: 'manufacturer', category: 'sneakers' },
  { name: 'ASICS', type: 'manufacturer', category: 'sneakers' },
  { name: 'Under Armour', type: 'manufacturer', category: 'sneakers' },
  { name: 'Hoka', type: 'manufacturer', category: 'sneakers', aliases: ['Hoka One One'] },
  { name: 'On Running', type: 'manufacturer', category: 'sneakers', aliases: ['On'] },
  { name: 'Salomon', type: 'manufacturer', category: 'sneakers' },
  { name: 'Balenciaga', type: 'manufacturer', category: 'sneakers' },
  { name: 'Off-White', type: 'brand', category: 'sneakers', aliases: ['Off White'] },
];

// Luxury Fashion
const FASHION: GlobalEntity[] = [
  { name: 'Louis Vuitton', type: 'manufacturer', category: 'fashion', aliases: ['LV'] },
  { name: 'Gucci', type: 'manufacturer', category: 'fashion' },
  { name: 'Hermès', type: 'manufacturer', category: 'fashion', aliases: ['Hermes'] },
  { name: 'Chanel', type: 'manufacturer', category: 'fashion' },
  { name: 'Prada', type: 'manufacturer', category: 'fashion' },
  { name: 'Dior', type: 'manufacturer', category: 'fashion', aliases: ['Christian Dior'] },
  { name: 'Versace', type: 'manufacturer', category: 'fashion' },
  { name: 'Fendi', type: 'manufacturer', category: 'fashion' },
  { name: 'Burberry', type: 'manufacturer', category: 'fashion' },
  { name: 'Givenchy', type: 'manufacturer', category: 'fashion' },
  { name: 'Bottega Veneta', type: 'manufacturer', category: 'fashion', aliases: ['Bottega'] },
  { name: 'Saint Laurent', type: 'manufacturer', category: 'fashion', aliases: ['YSL'] },
  { name: 'Valentino', type: 'manufacturer', category: 'fashion' },
  { name: 'Dolce & Gabbana', type: 'manufacturer', category: 'fashion', aliases: ['D&G'] },
  { name: 'Armani', type: 'manufacturer', category: 'fashion', aliases: ['Giorgio Armani'] },
  { name: 'Ralph Lauren', type: 'manufacturer', category: 'fashion', aliases: ['Polo'] },
  { name: 'Coach', type: 'manufacturer', category: 'fashion' },
  { name: 'Goyard', type: 'manufacturer', category: 'fashion' },
];

// Trading Cards
const CARDS: GlobalEntity[] = [
  { name: 'Pokemon', type: 'brand', category: 'trading_cards', aliases: ['Pokémon', 'Pokemon TCG'] },
  { name: 'Magic: The Gathering', type: 'brand', category: 'trading_cards', aliases: ['MTG', 'Magic'] },
  { name: 'Yu-Gi-Oh!', type: 'brand', category: 'trading_cards', aliases: ['Yugioh', 'YGO'] },
  { name: 'Topps', type: 'manufacturer', category: 'trading_cards' },
  { name: 'Panini', type: 'manufacturer', category: 'trading_cards' },
  { name: 'Upper Deck', type: 'manufacturer', category: 'trading_cards' },
  { name: 'PSA', type: 'company', category: 'trading_cards' },
  { name: 'BGS', type: 'company', category: 'trading_cards', aliases: ['Beckett'] },
];

// Famous Artists
const ARTISTS: GlobalEntity[] = [
  { name: 'Leonardo da Vinci', type: 'artist', category: 'art', aliases: ['Da Vinci'] },
  { name: 'Michelangelo', type: 'artist', category: 'art' },
  { name: 'Vincent van Gogh', type: 'artist', category: 'art', aliases: ['Van Gogh', 'van Gogh'] },
  { name: 'Claude Monet', type: 'artist', category: 'art', aliases: ['Monet'] },
  { name: 'Pablo Picasso', type: 'artist', category: 'art', aliases: ['Picasso'] },
  { name: 'Salvador Dalí', type: 'artist', category: 'art', aliases: ['Dali', 'Salvador Dali'] },
  { name: 'Frida Kahlo', type: 'artist', category: 'art' },
  { name: 'Andy Warhol', type: 'artist', category: 'art', aliases: ['Warhol'] },
  { name: 'Jean-Michel Basquiat', type: 'artist', category: 'art', aliases: ['Basquiat'] },
  { name: 'Banksy', type: 'artist', category: 'art' },
  { name: 'Damien Hirst', type: 'artist', category: 'art' },
  { name: 'Jeff Koons', type: 'artist', category: 'art' },
  { name: 'Takashi Murakami', type: 'artist', category: 'art' },
  { name: 'KAWS', type: 'artist', category: 'art', aliases: ['Brian Donnelly'] },
  { name: 'Rembrandt', type: 'artist', category: 'art', aliases: ['Rembrandt van Rijn'] },
  { name: 'Gustav Klimt', type: 'artist', category: 'art', aliases: ['Klimt'] },
  { name: 'Edvard Munch', type: 'artist', category: 'art', aliases: ['Munch'] },
  { name: 'René Magritte', type: 'artist', category: 'art', aliases: ['Magritte'] },
  { name: 'Jackson Pollock', type: 'artist', category: 'art', aliases: ['Pollock'] },
  { name: 'Mark Rothko', type: 'artist', category: 'art', aliases: ['Rothko'] },
];

// Famous Athletes
const ATHLETES: GlobalEntity[] = [
  { name: 'Michael Jordan', type: 'athlete', category: 'sports', aliases: ['MJ', 'Air Jordan'] },
  { name: 'LeBron James', type: 'athlete', category: 'sports', aliases: ['King James'] },
  { name: 'Kobe Bryant', type: 'athlete', category: 'sports', aliases: ['Black Mamba'] },
  { name: 'Stephen Curry', type: 'athlete', category: 'sports', aliases: ['Steph Curry'] },
  { name: 'Tom Brady', type: 'athlete', category: 'sports', aliases: ['TB12'] },
  { name: 'Lionel Messi', type: 'athlete', category: 'sports', aliases: ['Messi'] },
  { name: 'Cristiano Ronaldo', type: 'athlete', category: 'sports', aliases: ['CR7'] },
  { name: 'Tiger Woods', type: 'athlete', category: 'sports' },
  { name: 'Muhammad Ali', type: 'athlete', category: 'sports', aliases: ['The Greatest'] },
  { name: 'Babe Ruth', type: 'athlete', category: 'sports', aliases: ['The Bambino'] },
  { name: 'Wayne Gretzky', type: 'athlete', category: 'sports', aliases: ['The Great One'] },
  { name: 'Serena Williams', type: 'athlete', category: 'sports' },
  { name: 'Roger Federer', type: 'athlete', category: 'sports' },
  { name: 'Usain Bolt', type: 'athlete', category: 'sports' },
  { name: 'Shohei Ohtani', type: 'athlete', category: 'sports' },
];

// Celebrities/Musicians
const CELEBRITIES: GlobalEntity[] = [
  { name: 'The Beatles', type: 'celebrity', category: 'music', aliases: ['Beatles'] },
  { name: 'Elvis Presley', type: 'celebrity', category: 'music', aliases: ['Elvis', 'The King'] },
  { name: 'Michael Jackson', type: 'celebrity', category: 'music', aliases: ['King of Pop'] },
  { name: 'Taylor Swift', type: 'celebrity', category: 'music' },
  { name: 'Beyoncé', type: 'celebrity', category: 'music', aliases: ['Beyonce'] },
  { name: 'Drake', type: 'celebrity', category: 'music' },
  { name: 'Kanye West', type: 'celebrity', category: 'music', aliases: ['Ye', 'Yeezy'] },
  { name: 'Travis Scott', type: 'celebrity', category: 'music', aliases: ['Cactus Jack'] },
  { name: 'BTS', type: 'celebrity', category: 'music' },
  { name: 'BLACKPINK', type: 'celebrity', category: 'music' },
  { name: 'Marilyn Monroe', type: 'celebrity', category: 'entertainment' },
  { name: 'Leonardo DiCaprio', type: 'celebrity', category: 'entertainment' },
];

// Tech/Electronics
const TECH: GlobalEntity[] = [
  { name: 'Apple', type: 'manufacturer', category: 'electronics' },
  { name: 'Samsung', type: 'manufacturer', category: 'electronics' },
  { name: 'Sony', type: 'manufacturer', category: 'electronics' },
  { name: 'Nintendo', type: 'manufacturer', category: 'electronics' },
  { name: 'PlayStation', type: 'brand', category: 'electronics', aliases: ['PS5'] },
  { name: 'Xbox', type: 'brand', category: 'electronics' },
  { name: 'Bose', type: 'manufacturer', category: 'electronics' },
  { name: 'Canon', type: 'manufacturer', category: 'electronics' },
  { name: 'Nikon', type: 'manufacturer', category: 'electronics' },
  { name: 'Leica', type: 'manufacturer', category: 'electronics' },
];

// Automotive
const AUTO: GlobalEntity[] = [
  { name: 'Ferrari', type: 'manufacturer', category: 'automotive' },
  { name: 'Lamborghini', type: 'manufacturer', category: 'automotive' },
  { name: 'Porsche', type: 'manufacturer', category: 'automotive' },
  { name: 'Mercedes-Benz', type: 'manufacturer', category: 'automotive', aliases: ['Mercedes'] },
  { name: 'BMW', type: 'manufacturer', category: 'automotive' },
  { name: 'Audi', type: 'manufacturer', category: 'automotive' },
  { name: 'Rolls-Royce', type: 'manufacturer', category: 'automotive', aliases: ['Rolls Royce'] },
  { name: 'Bentley', type: 'manufacturer', category: 'automotive' },
  { name: 'Aston Martin', type: 'manufacturer', category: 'automotive' },
  { name: 'McLaren', type: 'manufacturer', category: 'automotive' },
  { name: 'Bugatti', type: 'manufacturer', category: 'automotive' },
  { name: 'Tesla', type: 'manufacturer', category: 'automotive' },
];

// Combine all entities
export const GLOBAL_ENTITIES: GlobalEntity[] = [
  ...WATCHES, ...SNEAKERS, ...FASHION, ...CARDS,
  ...ARTISTS, ...ATHLETES, ...CELEBRITIES, ...TECH, ...AUTO
];

/**
 * Search global entities by query
 */
export function searchGlobalEntities(query: string, limit: number = 10): GlobalEntity[] {
  const q = query.toLowerCase().trim();
  if (q.length < 2) return [];

  const results: { entity: GlobalEntity; score: number }[] = [];

  for (const entity of GLOBAL_ENTITIES) {
    const nameLower = entity.name.toLowerCase();
    let score = 0;

    // Exact match
    if (nameLower === q) {
      score = 100;
    }
    // Starts with query
    else if (nameLower.startsWith(q)) {
      score = 90;
    }
    // Contains query
    else if (nameLower.includes(q)) {
      score = 70;
    }
    // Check aliases
    else if (entity.aliases) {
      for (const alias of entity.aliases) {
        const aliasLower = alias.toLowerCase();
        if (aliasLower === q) {
          score = 95;
          break;
        } else if (aliasLower.startsWith(q)) {
          score = 85;
          break;
        } else if (aliasLower.includes(q)) {
          score = 65;
          break;
        }
      }
    }

    if (score > 0) {
      results.push({ entity, score });
    }
  }

  // Sort by score descending
  results.sort((a, b) => b.score - a.score);
  return results.slice(0, limit).map(r => r.entity);
}
